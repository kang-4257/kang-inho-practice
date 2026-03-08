# --- import ---
import os
import re
import httpx
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.sql import func
from passlib.context import CryptContext
from google import genai
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SECRET_KEY", "supersecretkey-change-in-production")
)

BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# --- DB ---
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST", "postgres_db")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "postgres")
DB_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DB_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

# Polaris 서비스 주소 (k3s 클러스터 내부)
POLARIS_URL = os.getenv("POLARIS_URL", "http://polaris-dashboard.polaris.svc.cluster.local:80")

# --- DB 모델 ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="user")
    posts = relationship("Post", back_populates="owner")

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    content = Column(String)
    summary = Column(String, nullable=True)
    status = Column(String, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, server_default=func.now())
    owner = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="post")

class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(String)
    post_id = Column(Integer, ForeignKey("posts.id"))
    owner_id = Column(Integer, ForeignKey("users.id"))
    post = relationship("Post", back_populates="comments")

class TrivyScan(Base):
    __tablename__ = "trivy_scans"
    id = Column(Integer, primary_key=True, index=True)
    scanned_at = Column(DateTime, server_default=func.now())
    image_tag = Column(String, nullable=True)
    critical = Column(Integer, default=0)
    high = Column(Integer, default=0)
    medium = Column(Integer, default=0)
    low = Column(Integer, default=0)
    report_text = Column(String, nullable=True)
    ai_guide = Column(String, nullable=True)
    vuln_logs = relationship("VulnerabilityLog", back_populates="scan")

class VulnerabilityLog(Base):
    __tablename__ = "vulnerability_logs"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("trivy_scans.id"))
    cve_id = Column(String, nullable=True)
    severity = Column(String, nullable=True)
    description = Column(String, nullable=True)
    ai_analysis_report = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    scan = relationship("TrivyScan", back_populates="vuln_logs")

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- 헬퍼 ---
def get_current_user(request: Request):
    if request.session.get("user_id"):
        return {
            "id": request.session.get("user_id"),
            "username": request.session.get("username"),
            "role": request.session.get("role")
        }
    return None

def require_admin(request: Request):
    user = get_current_user(request)
    if not user or user["role"] != "admin":
        return None
    return user

async def get_ai_summary(content: str):
    try:
        response = client.models.generate_content(
            model="gemini-1.5-flash",
            contents=f"다음 글을 한 줄로 요약해줘: {content}"
        )
        return response.text
    except Exception as e:
        print(f"AI Summary Error: {str(e)}")
        return "AI 요약 일시 중단"

async def fetch_polaris_summary():
    """Polaris HTML에서 summary 데이터 파싱"""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client_http:
            response = await client_http.get(f"{POLARIS_URL}/")
            html = response.text
            match = re.search(r'window\.polarisSummary\s*=\s*({[^}]+})', html)
            if match:
                import json
                data = json.loads(match.group(1))
                s = data.get("Successes", 0)
                w = data.get("Warnings", 0)
                d = data.get("Dangers", 0)
                total = s + w + d
                score = round((s / total) * 100) if total > 0 else 0
                # 바 차트용 퍼센트 미리 계산
                return {
                    "successes": s,
                    "warnings": w,
                    "dangers": d,
                    "score": score,
                    "success_pct": round(s / total * 100) if total > 0 else 0,
                    "warn_pct": round(w / total * 100) if total > 0 else 0,
                    "danger_pct": round(d / total * 100) if total > 0 else 0,
                    "url": os.getenv("POLARIS_EXTERNAL_URL", "http://localhost:30081")
                }
    except Exception as e:
        print(f"Polaris fetch error: {str(e)}")
    return {
        "successes": 0, "warnings": 0, "dangers": 0,
        "score": 0, "success_pct": 0, "warn_pct": 0, "danger_pct": 0,
        "url": "http://localhost:30081"
    }

# ========================
# --- 일반 유저 라우트 ---
# ========================

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    if get_current_user(request):
        return RedirectResponse(url="/main", status_code=303)
    error = request.query_params.get("error")
    success = request.query_params.get("success")
    return templates.TemplateResponse("login.html", {"request": request, "error": error, "success": success})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    error = request.query_params.get("error")
    return templates.TemplateResponse("register.html", {"request": request, "error": error})

@app.post("/register")
def register(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        return RedirectResponse(url="/register?error=exists", status_code=303)
    safe_pw = password.encode('utf-8')[:72].decode('utf-8', 'ignore')
    hashed_pw = pwd_context.hash(safe_pw)
    new_user = User(username=username, hashed_password=hashed_pw, role="user")
    db.add(new_user)
    db.commit()
    return RedirectResponse(url="/?success=registered", status_code=303)

@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return RedirectResponse(url="/?error=notfound", status_code=303)
    safe_pw = password.encode('utf-8')[:72].decode('utf-8', 'ignore')
    if not pwd_context.verify(safe_pw, user.hashed_password):
        return RedirectResponse(url="/?error=invalid", status_code=303)
    request.session["user_id"] = user.id
    request.session["username"] = user.username
    request.session["role"] = user.role
    # admin이면 admin 대시보드로
    if user.role == "admin":
        return RedirectResponse(url="/admin", status_code=303)
    return RedirectResponse(url="/main", status_code=303)

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=303)

@app.get("/main", response_class=HTMLResponse)
async def main_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    posts = db.query(Post).order_by(Post.id.desc()).all()
    # 작성일 KST 변환
    from datetime import timedelta
    for post in posts:
        if post.created_at:
            post.created_at = post.created_at + timedelta(hours=9)
    return templates.TemplateResponse("main.html", {"request": request, "posts": posts, "current_user": user})

@app.get("/write", response_class=HTMLResponse)
async def write_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse("write.html", {"request": request, "current_user": user})

@app.post("/write")
async def write_post(
    request: Request,
    title: str = Form(...),
    content: str = Form(...),
    db: Session = Depends(get_db)
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    ai_summary = await get_ai_summary(content)
    new_post = Post(title=title, content=content, status="normal", summary=ai_summary, owner_id=user["id"])
    db.add(new_post)
    db.commit()
    return RedirectResponse(url="/main", status_code=303)

@app.get("/post/{post_id}", response_class=HTMLResponse)
async def post_detail(post_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    # 작성일 KST 변환
    from datetime import timedelta
    if post.created_at:
        post.created_at = post.created_at + timedelta(hours=9)
    return templates.TemplateResponse("post_detail.html", {"request": request, "post": post, "current_user": user})

@app.get("/post/{post_id}/edit", response_class=HTMLResponse)
async def edit_page(post_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post or post.owner_id != user["id"]:
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    return templates.TemplateResponse("edit.html", {"request": request, "post": post, "current_user": user})

@app.post("/post/{post_id}/edit")
async def edit_post(
    post_id: int, request: Request,
    title: str = Form(...), content: str = Form(...),
    db: Session = Depends(get_db)
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post or post.owner_id != user["id"]:
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    post.title = title
    post.content = content
    db.commit()
    return RedirectResponse(url=f"/post/{post_id}", status_code=303)

@app.post("/post/{post_id}/delete")
async def delete_post(post_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post or (post.owner_id != user["id"] and user["role"] != "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    db.query(Comment).filter(Comment.post_id == post_id).delete()
    db.delete(post)
    db.commit()
    if user["role"] == "admin":
        return RedirectResponse(url="/admin/posts", status_code=303)
    return RedirectResponse(url="/main", status_code=303)

@app.get("/my-posts", response_class=HTMLResponse)
async def my_posts(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    posts = db.query(Post).filter(Post.owner_id == user["id"]).order_by(Post.id.desc()).all()
    return templates.TemplateResponse("my_posts.html", {"request": request, "posts": posts, "current_user": user})

# ========================
# --- Admin 라우트 ---
# ========================

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    user = require_admin(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)

    polaris = await fetch_polaris_summary()
    total_users = db.query(User).count()
    total_posts = db.query(Post).count()
    latest_scan = db.query(TrivyScan).order_by(TrivyScan.id.desc()).first()

    # 스캔 시각 KST 변환
    from datetime import timedelta
    if latest_scan and latest_scan.scanned_at:
        latest_scan.scanned_at = latest_scan.scanned_at + timedelta(hours=9)
    grafana_url = os.getenv("GRAFANA_EXTERNAL_URL", "http://localhost:30000")

    return templates.TemplateResponse("admin/dashboard.html", {
        "request": request,
        "current_user": user,
        "polaris": polaris,
        "total_users": total_users,
        "total_posts": total_posts,
        "latest_scan": latest_scan,
        "grafana_url": grafana_url
    })

@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users(request: Request, db: Session = Depends(get_db)):
    user = require_admin(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    users = db.query(User).all()
    return templates.TemplateResponse("admin/users.html", {"request": request, "current_user": user, "users": users})

@app.post("/admin/users/{user_id}/delete")
async def admin_delete_user(user_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_admin(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    target = db.query(User).filter(User.id == user_id).first()
    if not target or target.role == "admin":
        raise HTTPException(status_code=403, detail="삭제할 수 없습니다.")
    db.query(Post).filter(Post.owner_id == user_id).delete()
    db.delete(target)
    db.commit()
    return RedirectResponse(url="/admin/users", status_code=303)

@app.get("/admin/posts", response_class=HTMLResponse)
async def admin_posts(request: Request, db: Session = Depends(get_db)):
    user = require_admin(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    posts = db.query(Post).order_by(Post.id.desc()).all()
    return templates.TemplateResponse("admin/posts.html", {"request": request, "current_user": user, "posts": posts})

@app.get("/admin/trivy", response_class=HTMLResponse)
async def admin_trivy(request: Request, db: Session = Depends(get_db)):
    user = require_admin(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    scans = db.query(TrivyScan).order_by(TrivyScan.id.desc()).all()

    # 스캔 시각 KST 변환
    from datetime import timedelta
    for scan in scans:
        if scan.scanned_at:
            scan.scanned_at = scan.scanned_at + timedelta(hours=9)

    return templates.TemplateResponse("admin/trivy.html", {"request": request, "current_user": user, "scans": scans})

@app.get("/admin/trivy/{scan_id}/vulns", response_class=HTMLResponse)
async def admin_vulns(scan_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_admin(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    scan = db.query(TrivyScan).filter(TrivyScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="스캔 기록을 찾을 수 없습니다.")
    vulns = db.query(VulnerabilityLog).filter(VulnerabilityLog.scan_id == scan_id).all()

    # 심각도 순 정렬 (CRITICAL > HIGH > MEDIUM > LOW)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    vulns = sorted(vulns, key=lambda v: severity_order.get(v.severity, 99))
    return templates.TemplateResponse("admin/vulns.html", {
        "request": request,
        "current_user": user,
        "scan": scan,
        "vulns": vulns
    })

# GitHub Actions에서 Trivy 결과 전송받는 API
@app.post("/api/trivy-report")
async def receive_trivy_report(
    request: Request,
    db: Session = Depends(get_db)
):
    # API 키 인증
    api_key = request.headers.get("X-API-Key")
    if api_key != os.getenv("INTERNAL_API_KEY", "changeme"):
        raise HTTPException(status_code=401, detail="Unauthorized")

    body = await request.json()
    scan = TrivyScan(
        image_tag=body.get("image_tag"),
        critical=body.get("critical", 0),
        high=body.get("high", 0),
        medium=body.get("medium", 0),
        low=body.get("low", 0),
        report_text=body.get("report_text"),
        ai_guide=body.get("ai_guide")
    )
    db.add(scan)
    db.flush()  # scan.id 확보

    # CVE별 상세 기록 저장
    for cve in body.get("cves", []):
        log = VulnerabilityLog(
            scan_id=scan.id,
            cve_id=cve.get("cve_id"),
            severity=cve.get("severity"),
            description=cve.get("description")
        )
        db.add(log)

    db.commit()
    return {"message": "저장 완료"}

@app.get("/ai-test")
async def test_gemini():
    try:
        response = client.models.generate_content(model="gemini-2.0-flash-lite", contents="HI")
        return {"gemini_response": response.text}
    except Exception as e:
        return {"error": str(e)}      