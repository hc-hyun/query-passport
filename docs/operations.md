# 운영 경계

현재 구현은 로컬 PostgreSQL 18과 Docker용 MVP다. Query Man 스킬은 계획·사용자 소통을 맡고,
Passport는 닫힌 입력·대상 검증, 인증서 준비, 실행과 정제된 결과를 맡는다.

## 실행 범위

- 공개 요청의 alias를 operator의 private binding에 대조한다. Container/image/network/identity와
  계획 이후 설정 변경을 확인하며 대상이 다르면 중단한다.
- 승인된 대상·범위를 재사용한다. 문서 작성과 내부 코드 개발이 기존 DB 변경 승인은 아니다.
- `inspect`·`plan`은 오프라인이다. 실행 가능한 준비는 별도 live `prepare`다.
- 확인 계정과 인증 설정만 준비한다. DB·source·업무 객체·reader 권한·application readiness를 만들거나 재정의하지 않는다.
- 같은 대상의 변경은 lock으로 직렬화한다. 기존 role/grant/server credential/trust와 다른 서비스 설정은 보존한다.
- 확인 계정은 NOLOGIN으로 시작하고 인증 규칙이 로드된 후 LOGIN으로 전환한다. 기존 PUBLIC 권한이
  업무 접근·CREATE·TEMP를 부여하면 거절한다. 좁게 승인된 monitoring digest 예외는 [로컬 설정](local-lifecycle.md)에 있다.

## 비밀정보

CA/client private key, 인증서 원문, password, token, 인증정보 포함 DSN, 실제 Secret은 Git,
image, CLI argument, 환경변수, 채팅과 일반 로그에 넣지 않는다. CA key는 private PKI 경계에 둔다.
기존 credential을 탐색하거나 전체 환경·Docker inspect·Secret을 출력하지 않는다.
Runtime에는 승인된 bundle의 세 파일만 읽기 전용으로 전달한다. 입력·비밀 파일은 symlink와
넓은 쓰기 권한을 거절한다. Password fallback, 약한 TLS, 넓은 grant로 실패를 우회하지 않는다.

## 실패 동작

명령은 한 번 실행하고 실패하면 정제된 오류와 비영 종료를 반환한다. 자동 재시도·추가 DB 보상 변경·
rollback은 없다. 원인을 해결한 뒤 같은 작업 참조로 재실행한다. 기존 완료 결과는 동일성을 검사하고
재사용하며 불완전한 파일·타인 변경을 덮어쓰지 않는다. 일부 실패는 별도 수동 조치가 필요할 수 있다.

Timeout·프로세스 중단은 외부 변경을 취소하지 않는다. `status`는 마지막 기록일 뿐 현재 DB 상태의
증명이 아니다. 신규 credential은 실제 검증이 끝나기 전에는 활성화하지 않는다.
이전 세대와 기존 호스트 백업·기록은 보존한다. 로컬 실행 기록은 protected immutable evidence가 아니다.

## 지원하지 않는 운영 기능

Kubernetes/Secret provider, 운영 PKI 연계, 폐기, CA 교체, 자동 갱신·장애 복구·배포 rollout은 미구현이다.
같은 CA로 새 인증서를 발급해도 이전 인증서가 자동 폐기되지는 않는다.
Source 0개로 DB 접속이 성공해도 Query Man 앱 활성화나 업무 조회 준비 완료로 보고하지 않는다.
