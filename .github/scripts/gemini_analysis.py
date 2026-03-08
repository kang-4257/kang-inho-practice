import os
import datetime
import sys
import pytz
import requests
from google import genai

def main():
    # API 키 확인
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[에러] GEMINI_API_KEY 누락", file=sys.stderr)
        return

    client = genai.Client(api_key=api_key)

    # trivy 리포트 읽기
    try:
        with open("trivy-report.txt", "r", encoding="utf-8") as f:
            scan_result = f.read()
    except FileNotFoundError:
        print("[에러] trivy-report.txt 없음", file=sys.stderr)
        return

    # 취약점 개수 파싱
    critical = scan_result.count("CRITICAL")
    high = scan_result.count("HIGH")
    medium = scan_result.count("MEDIUM")
    low = scan_result.count("LOW")

    # 이미지 태그 읽기
    image_tag = os.getenv("IMAGE_TAG", "unknown")

    # KST 시간 생성
    kst = pytz.timezone('Asia/Seoul')
    kst_now = datetime.datetime.now(kst)
    current_time = kst_now.strftime("%Y년 %m월 %d일 %H시 %M분")

    # Gemini 분석 프롬프트
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
        print("[정보] Gemini 분석 중...", file=sys.stderr)
        response = client.models.generate_content(
            model="gemini-1.5-flash",
            contents=prompt
        )
        final_report = response.text.strip()

        # 파일 저장 (GitHub Issue용)
        with open("gemini-analysis.txt", "w", encoding="utf-8") as f:
            f.write(final_report)

        print("✅ 분석 완료", file=sys.stderr)

        # DB로 전송
        internal_api_key = os.getenv("INTERNAL_API_KEY")
        if internal_api_key:
            payload = {
                "image_tag": image_tag,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "report_text": scan_result[:5000],
                "ai_guide": final_report
            }
            res = requests.post(
                "http://localhost:30080/api/trivy-report",
                json=payload,
                headers={"X-API-Key": internal_api_key},
                timeout=10
            )
            if res.status_code == 200:
                print("✅ DB 저장 완료", file=sys.stderr)
            else:
                print(f"⚠️ DB 저장 실패: {res.text}", file=sys.stderr)
        else:
            print("⚠️ INTERNAL_API_KEY 누락, DB 저장 건너뜀", file=sys.stderr)

    except Exception as e:
        print(f"[에러] 분석 실패: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()