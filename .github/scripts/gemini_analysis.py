import os
import google.generativeai as genai

# 깃허브 액션에서 돌아갈 보안 분석
def main():
    # 저장해둔 API 키 가져오기
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[에러] GEMINI_API_KEY 누락됨.")
        return
    
    # 제미나이 설정
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-2.0-flash-lite')

    # 트리비가 스캔해서 만들어준 파일 열기
    try:
        with open("trivy-report.txt", "r") as f:
            # 앞부분 3000자만 읽어서 토큰 제한 회피
            scan_result = f.read(3000) 
    except FileNotFoundError:
        print("[에러] trivy-report.txt 파일 없음.")
        return

    prompt = f"""
    보안 전문가로서 다음 Trivy 스캔 결과를 분석해줘.
    중요도(Critical, High)가 높은 항목을 우선으로 리포트를 작성할 것.
    취약점의 원인 및 Dockerfile 수정 예시를 반드시 포함할 것.
    개수에 상관없이 진짜 위험한 건 다 알려주되, 너무 많으면 핵심적인 것 위주로 깔끔하게 정리할 것.

    스캔 결과 데이터:
    {scan_result}
    """
    
    # 제미나이 답변 생성
    response = model.generate_content(prompt)
    
    # 분석 결과를 파일로 저장
    with open("gemini-analysis.txt", "w", encoding="utf-8") as f:
        f.write(response.text)
    
    print("분석 및 보고서 작성 완료.")

if __name__ == "__main__":
    main()
