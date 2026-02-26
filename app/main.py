from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
import os

# --- DB 연결 설정 ---
DB_URL = "postgresql://myuser:mypassword@localhost:5432/mydatabase"

# DB 엔진 및 세션 생성
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- 보안 설정 ---
# bcrypt 알고리즘을 사용한 비밀번호 암호화 설정
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

Base.metadata.create_all(bind=engine)
# --- DB 연결 테스트용 로직 ---
@app.get("/")
def read_root():
    try:
        # DB 연결 상태 확인을 위해 세션 생성 테스트
        db = SessionLocal()
        db.execute(text("SELECT 1")) 
        return {"message": "Hello World", "db_status": "connected"}
    except Exception as e:
        return {"message": "Hello World", "db_status": f"error: {str(e)}"}
    finally:
        db.close()

# --- 비밀번호 암호화 함수 ---
def get_password_hash(password):
    # 평문 비번을 받아 bcrypt로 해싱 처리함
    return pwd_context.hash(password)

# --- Pydantic 모델 (입력값 검증용) ---
class UserRequest(BaseModel):
    username: str
    password: str

# --- DB 테이블 모델 (SQLAlchemy) ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

# DB 세션 생성 함수
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- API 구현 ---

# 1. 회원가입 (POST /register)
@app.post("/register")
def register(user_data: UserRequest, db: Session = Depends(get_db)):
    # 중복 유저 체크
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="이미 존재하는 아이디입니다.")
    
    # 비번 암호화 및 저장
    hashed_pw = pwd_context.hash(user_data.password) 
    new_user = User(username=user_data.username, hashed_password=hashed_pw)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "회원가입 성공", "username": new_user.username}

# 2. 로그인 (POST /login)
@app.post("/login")
def login(user_data: UserRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == user_data.username).first()
    
    # 사용자 존재 여부 및 비번 검증 (pwd_context.verify 사용)
    if not user or not pwd_context.verify(user_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 틀렸습니다.")
    
    return {"message": "로그인 성공", "username": user.username}
