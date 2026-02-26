from fastapi import FastAPI
from sqlalchemy import create_engine, Column, Integer, String, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext

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
