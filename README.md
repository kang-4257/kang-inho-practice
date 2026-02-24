# team-02
Team 02 - MSP Architect Training 2026

Trivy와 Gemini AI를 활용한 지능형 보안 진단 및 자동 조치 인프라

Ubuntu/K3s 환경에서 보안 취약점을 감지하는 것을 넘어, Gemini AI를 통해 실질적인 패치 코드와 보안 정책을 스스로 제시하는 지능형 DevSecOps 파이프라인 구축

주요 기능 (Main Features)
- AI 지능형 진단: Trivy 스캔 결과를 AI가 정밀 분석하여 취약점별 맞춤형 수정 코드(Patch) 자동 생성.

- Zero-Trust 네트워크 격리: web 및 db 네임스페이스 분리 및 L4 Network Policy를 통한 마이크로 세그멘테이션 적용.

- 선제적 보안 게이트(Gatekeeper): 이미지 빌드 단계에서 고위험 취약점 발견 시 배포를 자동 차단하여 보안 무결성 확보.
