import os
import google.generativeai as genai

def start_analysis():
    # 1. API 키 로드
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[에러] GEMINI_API_KEY 누락됨.")
        return 

    genai.configure(api_key=api_key)

    # 2. 사용 가능한 모델 목록 출력 (디버깅용)
    print("--- 사용 가능한 모델 목록 ---")
    try:
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
                print(f"모델 이름: {m.name}")
except Exception as e:
        print(f"[에러] 목록 가져오기 실패: {e}")

    # 3. 제미나이 설정 (2.0 모델)
    model = genai.GenerativeModel('gemini-2.0-flash-lite')

    # 4. 트리비 리포트 읽기
    try:
        with open("trivy-report.txt", "r") as f:
            # 쿼터 방어를 위해 1000자만 읽기
            scan_result = f.read(1000) 
    except FileNotFoundError:
        print("[에러] trivy-report.txt 파일 없음.")
        return

    # 5. 분석 요청
    prompt = f"보안 전문가로서 아래 결과 요약하고 Dockerfile 수정 제안해줘. \n\n{scan_result}"
    
    try:
        response = model.generate_content(prompt)
        with open("gemini-analysis.txt", "w", encoding="utf-8") as f:
            f.write(response.text)
        print("[성공] 분석 완료!")
    except Exception as e:
        print(f"[에러] 호출 실패: {e}")


if __name__ == "__main__":
    start_analysis()
