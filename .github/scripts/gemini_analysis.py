import os
import google.generativeai as genai
import datetime

def main():
    # 1. API 키 로드
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[에러] GEMINI_API_KEY 누락됨.")
        return
    
    genai.configure(api_key=api_key)



    # 2. 제미나이 설정
    model = genai.GenerativeModel('gemini-2.5-flash')

    # 3. 트리비 리포트 읽기
    try:
        with open("trivy-report.txt", "r") as f:
            scan_result = f.read(2000) 
    except FileNotFoundError:
        print("[에러] trivy-report.txt 파일 없음.")
        return

    current_time = datetime.datetime.now().strftime("%Y년 %m월 %d일 %H시 %M분")

    # 4. 분석 요청
    prompt = f"""
    당신은 시니어 DevSecOps 엔지니어입니다. 
    다음 Trivy 보안 스캔 결과를 바탕으로 '보안 취약점 개선 권고안'을 작성하세요.

    [리포트 헤더]
    날짜: {current_time}
    제목: Trivy 스캔 결과 기반 보안 강화 권고안

    [지시 사항]
    1. 리포트 서두에 "[정보] 리포트 분석 중..."이나 "Gemini 분석 완료" 같은 문구는 절대 포함하지 말 것.
    2. 가장 위험한(Critical, High) 항목 3가지를 우선 선정할 것.
    3. 각 취약점의 원인과 영향도를 한국어로 쉽게 설명할 것.
    4. 구체적인 'Dockerfile 수정 예시'를 (Before/After) 형태로 포함할 것.
    5. 보안 강화를 위한 추가적인 Best Practice(예: 멀티 스테이지 빌드, Root 권한 제한 등)를 제안할 것.

    [스캔 결과 데이터]
    {scan_result}
    """
    
    try:
        # 분석 실행
        print("[정보] 리포트 분석 중...")
        response = model.generate_content(prompt)
        
        # 결과 저장
        with open("gemini-analysis.txt", "w", encoding="utf-8") as f:
            f.write(response.text)
        print("✅ 분석 완료 및 파일 저장 성공.")
        
    except Exception as e:
        print(f"[에러] 분석 실패: {e}")

if __name__ == "__main__":
    main()
