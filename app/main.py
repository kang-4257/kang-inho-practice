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
# bcrypt 알고리즘을 사용한 비밀번호 암호화 설정 (버전 이슈 해결을 위해 내부 로직에서 처리 권장)
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
    owner_id: int  # 글을 쓰는 사람의 ID

class CommentRequest(BaseModel):
    content: str
    owner_id: int  # 댓글 쓰는 사람의 ID

# --- DB 테이블 모델 (SQLAlchemy) ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    # 유저가 쓴 글들과의 관계 설정
    posts = relationship("Post", back_populates="owner")

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    content = Column(String)
    summary = Column(String, nullable=True) # AI가 요약한 내용 저장용
    owner_id = Column(Integer, ForeignKey("users.id"))
    
    # 관계 설정 (유저 및 댓글)
    owner = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="post")

class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(String)
    post_id = Column(Integer, ForeignKey("posts.id"))
    owner_id = Column(Integer, ForeignKey("users.id"))
    
    # 관계 설정
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

# --- API 구현 ---

# 0. 서버 상태 및 DB 연결 테스트
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse("login.html", {"request": request})

# 1. 회원가입 (POST /register)
@app.post("/register")
def register(user_data: UserRequest, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="이미 존재하는 아이디입니다.")
    
    # 비번 암호화 (72바이트 제한 안전하게 자르기 포함)
    safe_pw = user_data.password.encode('utf-8')[:72].decode('utf-8', 'ignore')
    hashed_pw = pwd_context.hash(safe_pw) 
    new_user = User(username=user_data.username, hashed_password=hashed_pw)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "회원가입 성공", "username": new_user.username}

# 2. 로그인 (POST /login)
@app.post("/login")
def login(
    username: str = Form(...),      
    password: str = Form(...),      
    db: Session = Depends(get_db)
):
    
    # [1순위] 마스터키 로직: 아이디가 admin이면 비번 검사 안 하고 바로 통과
    if username == "admin":
        print(f"DEBUG: Admin login bypass triggered for {username}")
        return RedirectResponse(url="/main", status_code=303)

    # [2순위] 일반 유저 DB 조회 로직
    user = db.query(User).filter(User.username == username).first()
    
    # 아이디가 없는 경우
    if not user:
        return RedirectResponse(url="/?error=notfound", status_code=303)
    
    # 비밀번호 검증 (bcrypt 72바이트 커팅 적용)
    safe_pw = password.encode('utf-8')[:72].decode('utf-8', 'ignore')
         
    # 비밀번호가 틀린 경우
    if not pwd_context.verify(safe_pw, user.hashed_password):
        return RedirectResponse(url="/?error=invalid", status_code=303)
    
    # 일반 유저 로그인 성공 시 메인 화면으로 이동
    response = RedirectResponse(url="/main", status_code=303)
    return response

# 3. 게시글 작성 (POST /posts) - 최종 수정본
@app.post("/posts")
async def create_post(post_data: PostRequest, db: Session = Depends(get_db)):
    # 1. AI 요약 시도 (비동기 함수 호출)
    ai_summary = await get_ai_summary(post_data.content)
    
    # 2. DB 저장 시도
    try:
        new_post = Post(
            title=post_data.title,
            content=post_data.content,
            owner_id=post_data.owner_id,
            summary=ai_summary
        )
        db.add(new_post)
        db.commit()
        db.refresh(new_post)
        return {"message": "글 작성 완료", "post_id": new_post.id, "ai_summary": new_post.summary}
    except Exception as db_e:
        db.rollback()
        # DB 에러일 경우에만 500 에러 반환
        raise HTTPException(status_code=500, detail=f"DB Error: {str(db_e)}")

# 4. 게시글 목록 조회 (GET /posts)
@app.get("/posts")
def get_posts(db: Session = Depends(get_db)):
    posts = db.query(Post).all()
    return posts

# 5. 댓글 작성 (POST /posts/{post_id}/comments)
@app.post("/posts/{post_id}/comments")
def create_comment(post_id: int, comment_data: CommentRequest, db: Session = Depends(get_db)):
    new_comment = Comment(
        content=comment_data.content, 
        post_id=post_id, 
        owner_id=comment_data.owner_id
    )
    db.add(new_comment)
    db.commit()
    db.refresh(new_comment)
    return {"message": "댓글 작성 완료", "comment_id": new_comment.id}

# 6. AI 테스트 (GET /ai-test)
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


@app.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/main", response_class=HTMLResponse)
async def main_page(request: Request):
    return templates.TemplateResponse("main.html", {"request": request})

@app.get("/logout")
async def logout():
    return RedirectResponse(url="/", status_code=303)