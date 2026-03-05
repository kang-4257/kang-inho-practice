import os
import google.generativeai as genai
import datetime
import sys 

def main():
    # 1. API 키 로드
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[에러] GEMINI_API_KEY 누락됨.", file=sys.stderr)
        return
    
    genai.configure(api_key=api_key)

    # 2. 제미나이 설정
    model = genai.GenerativeModel('gemini-2.5-flash')

    # 3. 트리비 리포트 읽기
    try:
        with open("trivy-report.txt", "r", encoding="utf-8") as f:
            scan_result = f.read(2000) 
    except FileNotFoundError:
        print("[에러] trivy-report.txt 파일 없음.", file=sys.stderr)
        return

    # 날짜와 시간 생성
    current_time = datetime.datetime.now().strftime("%Y년 %m월 %d일 %H시 %M분")

    # 4. 분석 요청
    prompt = f"""
    당신은 시니어 DevSecOps 엔지니어입니다. 
    다음 Trivy 보안 스캔 결과를 바탕으로 '보안 취약점 개선 권고안'을 작성하세요.

    ### [리포트 필수 헤더 - 텍스트 한 글자도 바꾸지 말고 그대로 출력할 것]
    분석 일시: {current_time}
    제목: Trivy 스캔 결과 기반 보안 강화 권고안
    --------------------------------------------------

    [지시 사항]
    1. 위 '필수 헤더' 외에 "[정보]", "분석 완료" 같은 어떤 시스템 메시지도 리포트에 적지 말 것.
    2. 인사말이나 서론 없이 바로 분석 결과로 들어갈 것.
    3. 가장 위험한(Critical, High) 항목 3가지를 우선 선정할 것.
    4. 각 취약점의 원인과 영향도를 한국어로 쉽게 설명할 것.
    5. 구체적인 'Dockerfile 수정 예시'를 (Before/After) 형태로 포함할 것.
    6. 보안 강화를 위한 추가적인 Best Practice(예: 멀티 스테이지 빌드, Root 권한 제한 등)를 제안할 것.
    7. 과거의 실수는 절대 언급하지 말고 현재 데이터만 분석할 것.
    8. 마크다운 깨짐 방지를 위해 특수 기호(◆, ◇ 등)는 절대 사용하지 말 것.

    [스캔 결과 데이터]
    {scan_result}
    """
    
    try:
        # 분석 실행
        print("[정보] 리포트 분석 중...", file=sys.stderr)
        
        response = model.generate_content(prompt)
        
        # 앞뒤 공백 제거
        final_report = response.text.strip()
        
        # 결과 저장
        with open("gemini-analysis.txt", "w", encoding="utf-8") as f:
            f.write(final_report)
            
        print("✅ 분석 완료 및 파일 저장 성공.", file=sys.stderr)
        
    except Exception as e:
        print(f"[에러] 분석 실패: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()