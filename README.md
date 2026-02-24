# team-02
Team 02 - MSP Architect Training 2026

### Trivy와 Gemini AI를 활용한 지능형 보안 진단 및 자동 조치 인프라

Ubuntu/K3s 환경에서 보안 취약점을 감지하는 것을 넘어, Gemini AI를 통해 실질적인 패치 코드와 보안 정책을 스스로 제시하는 지능형 DevSecOps 파이프라인 구축

### 주요 기능 (Main Features)
- AI 지능형 진단: Trivy 스캔 결과를 AI가 정밀 분석하여 취약점별 맞춤형 수정 코드(Patch) 자동 생성.

- Zero-Trust 네트워크 격리: web 및 db 네임스페이스 분리 및 L4 Network Policy를 통한 마이크로 세그멘테이션 적용.

- 선제적 보안 게이트(Gatekeeper): 이미지 빌드 단계에서 고위험 취약점 발견 시 배포를 자동 차단하여 보안 무결성 확보.

- 통합 서비스 플랫폼 (Integrated Service Platform): 일반 사용자를 위한 게시판 서비스와 관리자를 위한 실시간 보안 관제 대시보드를 단일 엔드포인트에서 제공.

- Zero-Trust 인프라 실현: K3s 내부에 web과 db 네임스페이스를 물리적으로 분리하고, L4 Network Policy를 통해 외부 및 비인가 Pod의 데이터베이스 접근을 원천 차단.

- 실시간 보안 가시성 (Observability): 파이프라인에서 분석된 Trivy 및 Gemini AI의 리포트를 내부 DB와 연동하여, 인프라의 현재 보안 점수와 조치 가이드를 GUI 형태로 실시간 시각화.
