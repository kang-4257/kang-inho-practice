-- 1. 회원 테이블 (users)
CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. 게시판 테이블 (board)
CREATE TABLE IF NOT EXISTS board (
    post_id SERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    content TEXT,
    author_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. 보안 리포트 테이블 (security_reports)
CREATE TABLE IF NOT EXISTS security_reports (
    report_id SERIAL PRIMARY KEY,
    threat_level VARCHAR(20) NOT NULL, -- Low, Medium, High, Critical
    description TEXT,
    vulnerability_source TEXT, -- 예: Trivy, Gemini
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
