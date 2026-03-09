import os
import json
import datetime
import sys
import pytz
import requests
from google import genai

def parse_cves_from_json(json_path):
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[에러] JSON 읽기 실패: {e}", file=sys.stderr)
        return []

    cves = []
    seen = set()
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            cve_id = vuln.get("VulnerabilityID", "")
            if not cve_id or cve_id in seen:
                continue
            seen.add(cve_id)
            cves.append({
                "cve_id": cve_id,
                "severity": vuln.get("Severity", ""),
                "description": (vuln.get("Description") or vuln.get("Title") or "")[:500]
            })
    return cves

def analyze_with_gemini(prompt, api_key):
    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model="gemini-2.5-flash-lite",
        contents=prompt
    )
    return response.text.strip()

def analyze_with_groq(prompt, api_key):
    response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        },
        json={
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2048,
            "temperature": 0.3
        },
        timeout=60
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"].strip()

def main():
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    groq_api_key = os.getenv("GROQ_API_KEY")

    if not gemini_api_key and not groq_api_key:
        print("[에러] GEMINI_API_KEY, GROQ_API_KEY 둘 다 누락", file=sys.stderr)
        return

    try:
        with open("trivy-report.txt", "r", encoding="utf-8") as f:
            scan_result = f.read()
    except FileNotFoundError:
        print("[에러] trivy-report.txt 없음", file=sys.stderr)
        return

    cves = parse_cves_from_json("trivy-report.json")
    print(f"[정보] 파싱된 CVE: {len(cves)}개", file=sys.stderr)

    critical = sum(1 for c in cves if c["severity"] == "CRITICAL")
    high = sum(1 for c in cves if c["severity"] == "HIGH")
    medium = sum(1 for c in cves if c["severity"] == "MEDIUM")
    low = sum(1 for c in cves if c["severity"] == "LOW")

    image_tag = os.getenv("IMAGE_TAG", "unknown")

    kst = pytz.timezone('Asia/Seoul')
    kst_now = datetime.datetime.now(kst)
    current_time = kst_now.strftime("%Y년 %m월 %d일 %H시 %M분")

    critical_cves = [c for c in cves if c["severity"] == "CRITICAL"]
    high_cves = [c for c in cves if c["severity"] == "HIGH"]

    cve_summary = ""
    if critical_cves:
        cve_summary += "[ CRITICAL 취약점 ]\n"
        for c in critical_cves:
            cve_summary += f"- {c['cve_id']}: {c['description'][:200]}\n"
    if high_cves:
        cve_summary += "\n[ HIGH 취약점 ]\n"
        for c in high_cves:
            cve_summary += f"- {c['cve_id']}: {c['description'][:200]}\n"
    if not cve_summary:
        cve_summary = "Critical/High 취약점 없음"

    risk_level = "높음" if critical > 0 else "보통" if high > 3 else "낮음"
    fixed_header = (
        f"분석 일시: {current_time}\n\n"
        f"제목: Trivy 스캔 결과 기반 보안 강화 권고안\n\n"
        f"[스캔 현황 요약]\n\n"
        f"- 🚨 Critical: {critical}개\n"
        f"- ⚠️ High: {high}개\n"
        f"- 💡 Medium: {medium}개 / Low: {low}개\n"
        f"- 전체 위험 수준: {risk_level}\n\n"
        f"--------------------------------------------------"
    )

    # Gemini 전용 프롬프트 (상세 형식 지정)
    gemini_prompt = (
        "당신은 시니어 DevSecOps 엔지니어입니다.\n"
        "아래 Trivy 보안 스캔 결과를 바탕으로 보안 취약점 개선 권고안 본문만 작성하세요.\n\n"
        "### 출력 규칙 (반드시 준수)\n"
        "- 인사말(안녕하세요, 개발팀 여러분 등) 절대 금지.\n"
        "- 도입부 설명 문장 없이 바로 취약점 분석 본문 시작.\n"
        "- 특수 기호(◆, ◇ 등) 사용 금지.\n"
        "- 모든 설명은 반드시 한국어로 작성. CVE ID, 패키지명, 명령어 등 기술 용어만 영어 사용.\n"
        "- 취약점 영문 설명을 절대 그대로 출력하지 말고 반드시 한국어로 요약해서 작성.\n"
        "- 말투는 반드시 '~해야 합니다', '~될 수 있습니다', '~권고합니다' 형식으로 작성.\n"
        "- 각 항목 설명은 최소 3문장 이상 상세하게 작성.\n\n"
        "### 출력 형식 (반드시 아래 형식 그대로 사용)\n\n"
        "**Critical/High 취약점 섹션:**\n"
        "[ CRITICAL 취약점 ] 또는 [ HIGH 취약점 ] 제목 출력\n"
        "1. CVE-XXXX-XXXX: 취약점 한국어 이름\n"
        "   - **원인 및 영향도**: 취약점 발생 원인과 피해를 3문장 이상 상세히 설명.\n"
        "   - **조치 방법**: 구체적인 해결 방법과 주의사항을 2~3문장으로 설명.\n"
        "     - 수정 예시:\n"
        "       ```\n"
        "       # Before: 취약한 버전 - 구체적인 문제 설명 주석\n"
        "       RUN apt-get install -y 패키지명=취약한버전 (또는 pip install 패키지명==취약한버전)\n"
        "       # After: 패치된 버전으로 업데이트하여 취약점 해결\n"
        "       RUN apt-get install -y 패키지명=패치버전 (또는 pip install 패키지명==패치버전)\n"
        "       ```\n"
        "       실제 패키지명과 버전을 반드시 명시할 것.\n\n"
        "**Medium/Low 취약점 Best Practice 섹션 (반드시 포함, 절대 생략 금지):**\n"
        "[ Medium/Low 취약점 대응 Best Practice ]\n"
        "1. **항목 제목**: 배경 설명 후 구체적인 적용 방법과 명령어 예시까지 3문장 이상 작성.\n"
        "2. **항목 제목**: 배경 설명 후 구체적인 적용 방법과 명령어 예시까지 3문장 이상 작성.\n"
        "3. **항목 제목**: 배경 설명 후 구체적인 적용 방법과 명령어 예시까지 3문장 이상 작성.\n\n"
        "**종합 의견 (반드시 포함, '종합 의견' 제목 출력 후 내용 작성):**\n"
        "종합 의견\n"
        "현재 이미지 보안 상태 평가, 발견된 취약점 외 추가 고려사항 2~3가지, 향후 권고사항으로 구성.\n\n"
        "### 스캔 데이터\n"
        f"이미지 태그: {image_tag}\n"
        f"Critical: {critical}개 / High: {high}개 / Medium: {medium}개 / Low: {low}개\n\n"
        f"{cve_summary}\n"
    )

    # Groq 전용 프롬프트 (단순하고 직접적인 지시)
    groq_prompt = (
        "당신은 시니어 DevSecOps 엔지니어입니다.\n"
        "아래 Trivy 보안 스캔 결과를 바탕으로 보안 취약점 개선 권고안 본문만 작성하세요.\n\n"
        "### 규칙\n"
        "- 인사말, 도입부 문장 없이 바로 취약점 분석 시작.\n"
        "- 모든 설명은 한국어로 작성. CVE ID, 패키지명, 명령어만 영어 사용.\n"
        "- 취약점 영문 설명 그대로 출력 금지. 반드시 한국어로 요약.\n"
        "- 말투: '~해야 합니다', '~될 수 있습니다', '~권고합니다' 형식.\n"
        "- 각 항목 최소 3문장 이상 작성.\n\n"
        "### 출력 구조\n\n"
        "[ HIGH 취약점 ] 또는 [ CRITICAL 취약점 ] 제목 출력\n"
        "1. CVE-XXXX-XXXX: 취약점 한국어 이름\n"
        "- 원인 및 영향도: 원인과 피해를 3문장 이상 한국어로 설명\n"
        "- 조치 방법: 해결 방법을 2~3문장으로 설명\n"
        "  - 수정 예시 (한국어 주석 포함):\n"
        "    # Before: 취약한 버전 설명\n"
        "    (취약한 코드)\n"
        "    # After: 패치된 버전으로 업데이트\n"
        "    (수정된 코드)\n\n"
        "[ Medium/Low 취약점 대응 Best Practice ] (반드시 포함, 생략 금지)\n"
        "1. **항목 제목**: 배경 설명과 명령어 예시 포함하여 3문장 이상 작성\n"
        "2. **항목 제목**: 배경 설명과 명령어 예시 포함하여 3문장 이상 작성\n"
        "3. **항목 제목**: 배경 설명과 명령어 예시 포함하여 3문장 이상 작성\n\n"
        "종합 의견\n"
        "전반적인 보안 상태 평가, 추가 고려사항 2~3가지, 향후 권고사항 작성.\n\n"
        "### 스캔 데이터\n"
        f"이미지 태그: {image_tag}\n"
        f"Critical: {critical}개 / High: {high}개 / Medium: {medium}개 / Low: {low}개\n\n"
        f"{cve_summary}\n"
    )

    final_report = None

    # 1순위: Gemini
    if gemini_api_key:
        try:
            print("[정보] Gemini AI 분석 중...", file=sys.stderr)
            ai_body = analyze_with_gemini(gemini_prompt, gemini_api_key)
            final_report = fixed_header + "\n📌 분석 엔진: Gemini AI\n\n" + ai_body
            print("✅ Gemini 분석 완료", file=sys.stderr)
        except Exception as e:
            print(f"[경고] Gemini 실패: {e}", file=sys.stderr)
            print("[정보] Groq으로 fallback 시도...", file=sys.stderr)

    # 2순위: Groq fallback
    if final_report is None and groq_api_key:
        try:
            print("[정보] Groq AI 분석 중...", file=sys.stderr)
            ai_body = analyze_with_groq(groq_prompt, groq_api_key)
            final_report = fixed_header + "\n📌 분석 엔진: Groq AI (fallback)\n\n" + ai_body
            print("✅ Groq 분석 완료 (fallback)", file=sys.stderr)
        except Exception as e:
            print(f"[에러] Groq 분석 실패: {e}", file=sys.stderr)

    # 둘 다 실패
    if final_report is None:
        final_report = fixed_header + "\n\nAI 분석 생성 실패 (API 오류). 위 현황 요약을 참고하세요."

    with open("gemini-analysis.txt", "w", encoding="utf-8") as f:
        f.write(final_report)

    print("✅ 분석 완료", file=sys.stderr)

    # DB 저장
    internal_api_key = os.getenv("INTERNAL_API_KEY")
    if internal_api_key:
        payload = {
            "image_tag": image_tag,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "report_text": scan_result[:5000],
            "ai_guide": final_report,
            "cves": cves
        }
        try:
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
        except Exception as e:
            print(f"⚠️ DB 전송 오류: {e}", file=sys.stderr)
    else:
        print("⚠️ INTERNAL_API_KEY 누락, DB 저장 건너뜀", file=sys.stderr)

if __name__ == "__main__":
    main()