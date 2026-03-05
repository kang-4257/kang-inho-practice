import os
import google.generativeai as genai

# 깃허브 액션에서 돌아갈 보안 분석
def main():
    # 저장해둔 API 키 가져오기
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("에러: API 키가 없어서 분석을 못 하겠어.")
        return
    
    # 제미나이 설정
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-1.5-flash')

    # 트리비가 스캔해서 만들어준 파일 열기
    try:
        with open("trivy-report.txt", "r") as f:
            scan_result = f.read()
    except FileNotFoundError:
        print("에러: trivy-report.txt 파일이 없는데? 스캔이 안 된 건가?")
        return

    prompt = f"""
    너는 지금부터 보안 마스터야. 
    아래에 있는 Trivy 보안 스캔 결과를 보고 우리 팀을 위해 보안 리포트를 써줘.
    
    1. 발견된 모든 취약점 중에서 위험도(Critical, High)가 높은 순서대로 꼼꼼하게 분석해줘.
    2. 개수에 상관없이 진짜 위험한 건 다 알려주되, 너무 많으면 핵심적인 것 위주로 깔끔하게 정리해줘.
    3. 뭘 고쳐야 할지 Dockerfile 예시 코드까지 포함해서 한국어로 친절하게 설명해줘.
    
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
