import os
import google.generativeai as genai
import datetime
import sys
import pytz 

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
            scan_result = f.read() 
    except FileNotFoundError:
        print("[에러] trivy-report.txt 파일 없음.", file=sys.stderr)
        return

    # 날짜와 시간 생성
    kst = pytz.timezone('Asia/Seoul')
    kst_now = datetime.datetime.now(kst)
    current_time = kst_now.strftime("%Y년 %m월 %d일 %H시 %M분")

    # 4. 분석 요청
    prompt = f"""
    당신은 시니어 DevSecOps 엔지니어입니다. 
    다음 Trivy 보안 스캔 결과를 바탕으로 '보안 취약점 개선 권고안'을 작성하세요.

    ### [리포트 필수 헤더 - 텍스트 한 글자도 바꾸지 말고 그대로 출력할 것]
    분석 일시: {current_time}
    제목: Trivy 스캔 결과 기반 보안 강화 권고안

    [스캔 현황 요약]
    - 🚨 Critical: (스캔 결과에서 개수 추출)
    - ⚠️ High: (스캔 결과에서 개수 추출)
    - 💡 전체적인 위험 수준: (낮음/보통/높음 중 선택)
    --------------------------------------------------

    [지시 사항]
    1. 위 '필수 헤더' 및 '스캔 현황 요약' 외에 어떠한 시스템 메시지나 인사말도 적지 마라.
    2. 과거의 설정 오류는 언급하지 말고 오직 현재 데이터만 분석할 것.
    3. 마크다운 깨짐 방지를 위해 특수 기호(◆, ◇ 등)는 사용 금지.
    4. 언어 정책: 전체적인 설명과 가이드는 한국어로 작성하되, 핵심 전문 기술 용어는 영어를 그대로 사용하거나 병기하여 기술적 정확성을 높일 것.
    5. 모든 권고 사항은 개발자가 즉시 이해하고 적용할 수 있도록 실무적인 톤을 유지할 것.

    [리포트 구성 가이드]
    - 총 5가지 핵심 항목(취약점 3개 + Best Practice 2개)을 선정할 것.
    - 각 항목은 반드시 '원인/영향도 설명'과 'Dockerfile 수정 예시(Before/After)'를 포함할 것.

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