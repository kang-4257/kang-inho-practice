import os
import re
import json
import datetime
import sys
import pytz
import requests
from google import genai

def parse_cves_from_json(json_path):
    # trivy JSON에서 CVE 파싱
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

    # JSON에서 CVE 파싱
    cves = parse_cves_from_json("trivy-report.json")
    print(f"[정보] 파싱된 CVE: {len(cves)}개", file=sys.stderr)

    # 심각도별 개수 집계
    critical = sum(1 for c in cves if c["severity"] == "CRITICAL")
    high = sum(1 for c in cves if c["severity"] == "HIGH")
    medium = sum(1 for c in cves if c["severity"] == "MEDIUM")
    low = sum(1 for c in cves if c["severity"] == "LOW")

    # 이미지 태그 읽기
    image_tag = os.getenv("IMAGE_TAG", "unknown")

    # KST 시간 생성
    kst = pytz.timezone('Asia/Seoul')
    kst_now = datetime.datetime.now(kst)
    current_time = kst_now.strftime("%Y년 %m월 %d일 %H시 %M분")

    # Gemini에 넘길 CVE 요약 (Critical/High만 상세, 나머지는 개수만)
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

    # Gemini 분석 프롬프트
    prompt = f"""
당신은 시니어 DevSecOps 엔지니어입니다.
아래 Trivy 보안 스캔 결과를 바탕으로 '보안 취약점 개선 권고안'을 작성하세요.

### 리포트 헤더 (아래 내용을 한 글자도 바꾸지 말고 그대로 출력)
분석 일시: {current_time}
제목: Trivy 스캔 결과 기반 보안 강화 권고안

[스캔 현황 요약]
- 🚨 Critical: {critical}개
- ⚠️ High: {high}개
- 💡 Medium: {medium}개 / Low: {low}개
- 전체 위험 수준: {"높음" if critical > 0 else "보통" if high > 3 else "낮음"}
--------------------------------------------------

### 지시 사항
1. 헤더 이후 인사말, 시스템 메시지 없이 바로 본문 작성.
2. 특수 기호(◆, ◇ 등) 사용 금지.
3. 설명은 한국어로, 기술 용어(CVE ID, 패키지명 등)는 영어 그대로 사용.
4. 개발자가 즉시 적용 가능한 실무적 톤으로 작성.
5. 발견된 취약점이 없으면 현재 이미지가 안전하다고 간단히 명시.

### 리포트 구성
- Critical/High 취약점이 있으면 각각 원인/영향도와 조치 방법(Dockerfile 수정 예시 Before/After 포함)을 작성.
- Critical/High가 없으면 Medium 이하 주요 취약점 위주로 Best Practice 3가지를 권고.
- 마지막에 '종합 의견' 한 단락으로 마무리.

### 스캔 데이터
이미지 태그: {image_tag}
Critical: {critical}개 / High: {high}개 / Medium: {medium}개 / Low: {low}개

{cve_summary}
"""

    try:
        print("[정보] Gemini 분석 중...", file=sys.stderr)
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt
        )
        final_report = response.text.strip()

        # 파일 저장 (GitHub Issue용)
        with open("gemini-analysis.txt", "w", encoding="utf-8") as f:
            f.write(final_report)

        print("✅ 분석 완료", file=sys.stderr)

    except Exception as e:
        print(f"[에러] 분석 실패: {e}", file=sys.stderr)
        final_report = None

        # Gemini 실패해도 빈 파일 생성 (Create Issue 스텝 대비)
        with open("gemini-analysis.txt", "w", encoding="utf-8") as f:
            f.write("분석 리포트 생성 실패 혹은 취약점 없음.")

    # Gemini 성공 여부와 관계없이 CVE + 스캔 결과 DB 저장
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