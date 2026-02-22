# team-02
Team 02 - MSP Architect Training 2026

2-Tier 아키텍처 기반의 보안 강화 컨테이너 인프라 구축 및 취약점 분석
<img width="688" height="514" alt="image" src="https://github.com/user-attachments/assets/454d2175-90ac-475a-94b5-708768a7476a" />
침해 사고 발생 시 피해 범위를 최소화하는 심층 방어 구조 지향

### 🛠 선택 기술 및 선정 근거
| 분류 | 선택 기술 | 선정 근거 |
| :--- | :--- | :--- |
| **Orchestration** | **Kubernetes** | 다수의 컨테이너를 중앙 통제하고, NetworkPolicy를 통한 세밀한 보안 규칙 적용을 위해 선택. |
| **Web Server** | **Nginx** | 비동기 이벤트 기반으로 대량 접속에 유리하며, 리버스 프록시 설정을 통해 보안 계층 전면 배구 적합. |
| **Database** | **MySQL** | 표준적인 관계형 DB로, 2-Tier 구조 내 권한 분리 및 연결 제어 테스트 수행에 최적화됨. |
| **Security Tool** | **Trivy** | 이미지 빌드 단계에서 취약점을 즉시 식별하며, CI/CD 보안 자동화에 적합함. |
| **OS** | **Ubuntu** | 넓은 커뮤니티로 빠른 보안 패치 업데이트가 가능하며, K8s 환경에서 가장 안정적임. |

