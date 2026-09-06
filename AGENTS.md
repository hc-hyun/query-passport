# Query Passport 개발 안내

이 지침은 이 프로젝트 전체에 적용한다. Query Passport는 Query Man 스킬이 호출하는 DB 인증서와
접속 준비 도구다. 현재 M1 오프라인 CLI, M2 로컬 Docker 검증과 M3 로컬 발급·적용·전달·교체 MVP CLI를 구현했다.
기존 대상 전환과 Kubernetes·운영 PKI 연계는 별도 검증·개발 대상이다.

## 작업 시작

1. [README](README.md)에서 역할과 현재 상태를 읽는다.
2. [개발 계획](docs/development-plan.md)에서 진행할 첫 미완료 단계를 고른다.
3. 호출 계약은 [Tool contract](docs/tool-contract.md), 실제 변경·비밀정보·복구 경계는
   [운영 설계](docs/operations.md)를 따른다.
4. 기존 로컬 작업을 참고할 때만 [기존 작업 인계](docs/local-handoff.md)를 읽는다.

M1·M2와 M3 로컬 CLI·JSON 계약은 구현과 테스트로 고정했다. 이후 운영 backend의 예시는 설계안이며
현재 실행 가능한 기능으로 취급하지 않는다. 구현·검증이 완료된 범위만 현재 상태로 갱신한다.

## 구현 원칙

- Query Man 스킬이 계획과 사용자 소통을 맡고, 이 도구가 입력 검증·대상 확인·안전한 실행·결과
  정규화를 맡는다. 안전을 프롬프트나 호출자의 주의만으로 보장하지 않는다.
- 우선 하나의 CLI와 Python package로 구현한다. Python/uv는 초기 제안이며 첫 구현에서 고정한다.
  별도 HTTP service, MCP server, UI, 임의 plugin framework를 먼저 만들지 않는다.
- Query Man 앱은 이 도구에 런타임 의존하지 않는다. 기존 profile/credential layout을 보존하고
  source 정책, reader 권한과 application readiness를 도구가 다시 정의하지 않는다.
- DB만 등록하거나 접속을 확인하는 요청으로 source, 업무 view, base table 또는 DB를 만들지 않는다.
- 새 helper나 추상화는 실제 재사용 요구가 있을 때만 추가한다. 로컬 전용 스크립트를 일반 운영
  도구로 간주하지 말고 변경 전 검사·실패·복구 경로를 함께 이해한다.

## 실행과 비밀정보

- 이 문서 작성은 기존 DB, PKI, Secret 또는 Kubernetes의 변경 실행을 승인한 것이 아니다.
  실제 실행에서는 기존에 승인된 대상·범위를 재사용하고, 범위 밖의 변경만 추가로 확인한다.
  일반 문서 검토와 내부 코드 개발에 불필요한 실행 승인을 요구하지 않는다.
- 기존 Query Man의 외부 계약·인증 단위·권한·protected 운영 절차를 변경해야 하면 그 변경의
  현재/제안 의미와 영향을 먼저 제시한다. 새 도구 문서로 기존 계약을 덮어쓰지 않는다.
- CA/client private key, 인증서 원문, password, token, 인증정보 포함 DSN과 실제 Secret 내용은
  Git, image, CLI argument, 환경변수, 채팅, 일반 log에 넣지 않는다. CA key는 PKI 실행 경계에 둔다.
- 비밀 파일을 살펴보거나 환경·Docker inspect·Secret 전체 출력으로 인증정보를 찾아내지 않는다.
  승인된 alias 또는 credential-aware 실행 수단을 사용하고 agent에는 정제된 결과만 반환한다.
- 기존 호스트 credential·백업·실행 기록을 이 repo에 복사하거나 삭제하지 않는다. 실제 실행 기록은
  환경 기록 저장소에 추가 방식으로 보존한다. 로컬 JSONL을 protected immutable evidence로 부르지 않는다.
- SQL/인증 실패는 비밀 없는 분류 코드로 반환한다. weaker TLS, password fallback, 넓은 grant,
  무조건 덮어쓰기·revoke·drop으로 실패를 우회하지 않는다.

## 검증과 협업

- 테스트는 root `tests/`에서 관리한다. 입력/대상 검증, 비밀정보 비노출, 계획 이후 drift,
  일부 적용 오류·재실행과 실제 인증서 거부 조건을 의미 있는 테스트로 검증한다.
- 문서만 변경할 때는 링크·예시·현재/목표 상태의 일관성을 확인한다. 실제 수행하지 않은
  lint/type/test 통과나 운영 완료를 주장하지 않는다.
- 구현을 시작하면 실행 가능한 검사 명령과 최소 검증 환경을 개발 계획에 함께 추가한다.
- 병렬 작업은 파일 소유자를 먼저 정한다. 공통 문서·형식은 single-writer로 편집하며,
  Git 변경은 coordinating agent만 수행한다. 다른 작업의 변경을 되돌리지 않는다.
