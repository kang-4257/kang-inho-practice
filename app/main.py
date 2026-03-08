# --- (1) 모든 import 문 ---
import os
from pathlib import Path
from typing import List

from fastapi import FastAPI, HTTPException, Depends, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from passlib.context import CryptContext  
from google import genai
from dotenv import load_dotenv
  
load_dotenv()

app = FastAPI()

BASE_DIR = Path(__file__).resolve().parent

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
  
# --- DB 연결 설정 ---
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD") 
DB_HOST = os.getenv("DB_HOST", "postgres_db")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "postgres")

DB_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# DB 엔진 및 세션 생성
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- 보안 설정 ---  
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")  

# 최신 google-genai SDK 적용
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

# --- Pydantic 모델 (입력값 검증용) ---
class UserRequest(BaseModel):
    username: str
    password: str

class PostRequest(BaseModel):
    title: str
    content: str
    owner_id: int

class CommentRequest(BaseModel):
    content: str
    owner_id: int

# --- DB 테이블 모델 (SQLAlchemy) ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)    
    posts = relationship("Post", back_populates="owner")

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    content = Column(String)
    summary = Column(String, nullable=True)
    status = Column(String, nullable=True)  # 위험 레벨 (low / medium / high)
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

# 테이블 생성
Base.metadata.create_all(bind=engine)

# DB 세션 생성 함수
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- AI 요약 함수 ---
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

# --- API 구현 ---

# 0. 루트 - 로그인 페이지
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    error = request.query_params.get("error")
    return templates.TemplateResponse("login.html", {"request": request, "error": error})

# 1. 회원가입 페이지 (GET /register)
@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

# 2. 회원가입 처리 (POST /register) - Form 방식
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
    new_user = User(username=username, hashed_password=hashed_pw)
    
    db.add(new_user)
    db.commit()
    return RedirectResponse(url="/?success=registered", status_code=303)

# 3. 로그인 페이지 (GET /login)
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# 4. 로그인 처리 (POST /login) - Form 방식
@app.post("/login")
def login(
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
    
    return RedirectResponse(url="/main", status_code=303)

# 5. 메인 대시보드 (GET /main)
@app.get("/main", response_class=HTMLResponse)
async def main_page(request: Request, db: Session = Depends(get_db)):
    posts = db.query(Post).order_by(Post.id.desc()).all()
    return templates.TemplateResponse("main.html", {"request": request, "posts": posts})

# 6. 로그아웃
@app.get("/logout")
async def logout():
    return RedirectResponse(url="/", status_code=303)

# 7. 글쓰기 페이지 (GET /write)
@app.get("/write", response_class=HTMLResponse)
async def write_page(request: Request):
    return templates.TemplateResponse("write.html", {"request": request})

# 8. 글쓰기 처리 (POST /write) - Form 방식 + AI 요약
@app.post("/write")
async def write_post(
    title: str = Form(...),
    content: str = Form(...),
    status: str = Form(...),
    db: Session = Depends(get_db)
):
    ai_summary = await get_ai_summary(content)
    
    # owner_id=1 임시 고정 (세션 기능 추가 시 수정 필요)
    new_post = Post(
        title=title,
        content=content,
        status=status,
        summary=ai_summary,
        owner_id=1
    )
    db.add(new_post)
    db.commit()
    return RedirectResponse(url="/main", status_code=303)

# 9. 게시글 상세 (GET /post/{post_id})
@app.get("/post/{post_id}", response_class=HTMLResponse)
async def post_detail(post_id: int, request: Request, db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    return templates.TemplateResponse("post_detail.html", {"request": request, "post": post})

# 10. AI 테스트 (GET /ai-test)
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