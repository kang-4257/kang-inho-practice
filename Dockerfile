# 1. 베이스 이미지 설정
FROM python:3.11-slim

# 2. 필수 환경 변수 설정
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 3. 작업 디렉토리 생성
WORKDIR /app

# 4. glibc 업데이트 (CVE-2026-0861 대응)
RUN apt-get update && apt-get install -y --only-upgrade libc6 && rm -rf /var/lib/apt/lists/*

# 5. 비루트 사용자 생성 및 권한 설정
RUN useradd -m appuser
USER appuser

# 6. 의존성 파일 복사 및 설치
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# 7. 소스 코드 복사
COPY app/ .

# 8. 실행 경로 추가 및 포트 노출
ENV PATH="/home/appuser/.local/bin:${PATH}"
ENV PYTHONPATH=/app
EXPOSE 8000

# 9. 앱 실행 명령
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

#test2