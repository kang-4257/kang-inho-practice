# --- (1) 모든 import 문 ---
import os
from pathlib import Path  
 
from fastapi import FastAPI, HTTPException, Depends, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from passlib.context import CryptContext
from google import genai
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

# --- 세션 미들웨어 ---
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SECRET_KEY", "supersecretkey-change-in-production")
)

BASE_DIR = Path(__file__).resolve().parent  
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# --- DB 연결 ---
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST", "postgres_db")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "postgres")  
DB_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
  
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- 보안 설정 ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Gemini AI ---
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

# --- DB 모델 ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="user")  # "user" or "admin"
    posts = relationship("Post", back_populates="owner")

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    content = Column(String)
    summary = Column(String, nullable=True)
    status = Column(String, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="post")

class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(String)
    post_id = Column(Integer, ForeignKey("posts.id"))
    owner_id = Column(Integer, ForeignKey("users.id"))
    post = relationship("Post", back_populates="comments")
  
Base.metadata.create_all(bind=engine)
  
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- 세션 헬퍼 ---
def get_current_user(request: Request):
    """세션에서 현재 로그인한 유저 반환. 없으면 None."""
    if request.session.get("user_id"):
        return {
            "id": request.session.get("user_id"),
            "username": request.session.get("username"),
            "role": request.session.get("role")
        }
    return None

# --- AI 요약 ---
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

# ========================
# --- 라우트 ---
# ========================

# 루트 - 로그인 페이지
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    if get_current_user(request):
        return RedirectResponse(url="/main", status_code=303)
    error = request.query_params.get("error")
    success = request.query_params.get("success")
    return templates.TemplateResponse("login.html", {"request": request, "error": error, "success": success})

# 회원가입 페이지
@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    error = request.query_params.get("error")
    return templates.TemplateResponse("register.html", {"request": request, "error": error})

# 회원가입 처리
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

# 로그인 처리
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

    # 세션에 유저 정보 저장
    request.session["user_id"] = user.id
    request.session["username"] = user.username
    request.session["role"] = user.role

    return RedirectResponse(url="/main", status_code=303)

# 로그아웃
@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=303)

# 메인 게시판
@app.get("/main", response_class=HTMLResponse)
async def main_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    posts = db.query(Post).order_by(Post.id.desc()).all()
    return templates.TemplateResponse("main.html", {"request": request, "posts": posts, "current_user": user})

# 글쓰기 페이지
@app.get("/write", response_class=HTMLResponse)
async def write_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse("write.html", {"request": request, "current_user": user})

# 글쓰기 처리
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
    new_post = Post(
        title=title,
        content=content,
        status="normal",
        summary=ai_summary,
        owner_id=user["id"]
    )
    db.add(new_post)
    db.commit()
    return RedirectResponse(url="/main", status_code=303)

# 게시글 상세
@app.get("/post/{post_id}", response_class=HTMLResponse)
async def post_detail(post_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    return templates.TemplateResponse("post_detail.html", {"request": request, "post": post, "current_user": user})

# 게시글 수정 페이지
@app.get("/post/{post_id}/edit", response_class=HTMLResponse)
async def edit_page(post_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post or post.owner_id != user["id"]:
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    return templates.TemplateResponse("edit.html", {"request": request, "post": post, "current_user": user})

# 게시글 수정 처리
@app.post("/post/{post_id}/edit")
async def edit_post(
    post_id: int,
    request: Request,
    title: str = Form(...),
    content: str = Form(...),
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

# 게시글 삭제
@app.post("/post/{post_id}/delete")
async def delete_post(post_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post or post.owner_id != user["id"]:
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    db.query(Comment).filter(Comment.post_id == post_id).delete()
    db.delete(post)
    db.commit()
    return RedirectResponse(url="/main", status_code=303)

# 내가 쓴 글
@app.get("/my-posts", response_class=HTMLResponse)
async def my_posts(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    posts = db.query(Post).filter(Post.owner_id == user["id"]).order_by(Post.id.desc()).all()
    return templates.TemplateResponse("my_posts.html", {"request": request, "posts": posts, "current_user": user})

# AI 테스트
@app.get("/ai-test")
async def test_gemini():
    try:
        response = client.models.generate_content(
            model="gemini-2.0-flash-lite",
            contents="HI"
        )
        return {"gemini_response": response.text}
    except Exception as e:
        return {"error": str(e)}