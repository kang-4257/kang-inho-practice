# 1. 베이스 이미지 설정 (가볍고 보안에 강한 slim 버전)
FROM python:3.11-slim

# 2. 필수 환경 변수 설정 (파이썬 출력 최적화)
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 3. 작업 디렉토리 생성
WORKDIR /app

# 4. 비루트 사용자 생성 및 권한 설정
RUN useradd -m appuser
USER appuser

# 5. 의존성 파일 복사 및 설치 (사용자 권한으로 실행)
COPY --chown=appuser:appuser requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# 6. 소스 코드 복사
COPY --chown=appuser:appuser . .

# 7. 실행 경로 추가 및 포트 노출
ENV PATH="/home/appuser/.local/bin:${PATH}"
EXPOSE 8000

# 8. 앱 실행 명령
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

#test1