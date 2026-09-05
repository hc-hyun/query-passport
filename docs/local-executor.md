# 로컬 Docker executor

0.2.0의 `verify`는 직접 연결하는 PostgreSQL 18/UTF8와 로컬 Docker daemon을 지원한다.
`inspect`·`plan`은 계속 오프라인이며 `verify`의 성공이 앱/source readiness를 증명하지 않는다.
이 backend는 Query Man 이미지의 Python/psycopg를 UID/GID 10001:10001로 실행한다.
운영 PKI, Kubernetes, PgBouncer와 protected 실행 승인은 아직 지원하지 않는다.

## 설치와 호출

```bash
uv sync --locked
uv run --locked query-passport capabilities
uv run --locked query-passport verify --request examples/request.json
```

예시 alias에 binding을 구성하지 않은 상태에서 마지막 명령은 exit 6 /
`AUTHORIZATION_REQUIRED`다. 호스트명·alias·`approved: true`만으로 접속 권한을 만들 수 없다.
스킬은 `connection.verify.v1`과 계약 major 1을 확인한 뒤 이미 승인된 실행 범위에서만 호출한다.

## Operator binding

로컬 운영자가 별도 설치하는 파일은 OS 계정의 홈 기준
`~/.config/query-passport/executors/<target_alias>.json`이다. 공개 요청이나 스킬의 입력 파일이
아니다. 내부 credential 경로를 포함하므로 내용 전체를 agent·채팅·일반 log에 출력하지 않는다.
`HOME`, `DOCKER_HOST`, `.env`로 위치나 daemon을 바꿀 수 없다.

directory는 owner root 또는 실행 UID, mode `0700`, 파일은 같은 owner와 `0600`의 single-link
일반 파일이어야 한다. 모든 경로의 symlink와 신뢰하지 않는 계정이 변경 가능한 ancestor를 거절한다.
이것은 로컬 OS 계정의 권한에 의존하는 설정 경계다. 같은 계정의 악성 프로세스를 분리하거나
protected 승인·immutable 증거를 대신하는 장치는 아니다. 공개 API에 binding 경로 override는 없다.

| 필드 | 운영자가 고정할 값 |
|---|---|
| `binding_version` | 정수 `1` |
| `allowed_uid` | 호출을 허용한 실제 OS UID |
| `expires_at` | 승인 범위가 만료되는 UTC Unix 초(정수) |
| `operations` | 현재는 `["verify"]`만 지원 |
| `request` | 승인된 공개 요청의 사본. 별도 source inventory 증거는 아님 |
| `container_id` | 정확한 DB container ID 64자리 |
| `container_started_at` | 해당 container의 `.State.StartedAt` |
| `database_image_id` | DB 이미지의 `sha256:...` ID |
| `network_name`, `network_id` | 승인된 Docker network 이름과 64자리 ID |
| `hostaddr` | 위 network에서 해당 DB의 단일 IPv4 주소 |
| `runtime_image_id` | 승인된 Query Man runtime 이미지의 `sha256:...` ID |
| `runtime_uid`, `runtime_gid` | 각각 정수 `10001` |
| `username` | 이미 존재하고 승인된 확인 계정. 생성·grant는 수행하지 않음 |
| `expected_dn` | 단일 CN의 `CN=<소문자·숫자·하이픈 alias>` |
| `credential_dir` | 외부 관리 영역의 절대 directory 경로. 세 credential 파일만 포함 |

예시는 값 없는 필드 설명이다. 실제 container/network/image/generation은 승인된 대상의 선택적
metadata 검사로 확인한다. 전체 Docker inspect, 환경 변수, Secret 내용 덤프로 값을 찾지 않는다.
`local-synthetic`은 disposable fixture, `local`은 승인된 기존 로컬 대상이다. `protected`는
이 파일 방식으로 승인할 수 없다. 원본 profile의 환경·배포·profile·endpoint·DB·TLS 이름이
요청과 다르면 `TARGET_MISMATCH`로 첫 DB 접속 전에 거절한다.

## 실제 검증과 실행 경계

고정 local socket `/var/run/docker.sock`만 사용한다. DB container ID, 재시작 generation,
image, network ID와 IP를 실행 전후에 비교한다. DB 접속은 그 IP의 `hostaddr`에 고정하고,
`host`는 TLS 이름 검증에 사용한다. 다른 endpoint나 DNS 결과로 자동 우회하지 않는다.

새 검사 container는 승인된 runtime image ID로만 실행하며 자동 pull을 하지 않는다.
root filesystem과 credential mount는 읽기 전용이고 capability를 제거한다. image의 환경 변수도
초기화한 뒤 Python을 실행한다. `/run/secrets/query-man/databases/<profile>/`의 세 파일만
노출하며 그 외 파일이 있는 directory를 mount하지 않는다. Private key는 실행 UID의 `0600` 또는
root:10001의 `0640`이어야 한다. 최종 credential inode를 FD로 고정하고 전후 metadata drift를 확인한다.

worker는 원문 인증정보나 driver 오류를 출력하지 않는다. 고정 진단 SQL로 다음을 검사한다.

- 실제 TLS 1.2/1.3, 서버 CA·hostname, 정확한 client DN, DB·session_user·endpoint
- PostgreSQL 18, server/client UTF8, UTC·repeatable-read·read-only transaction
- statement timeout 뒤 rollback 및 같은 연결 복구
- 명시적 안전한 cancel 뒤 rollback 및 같은 연결 복구, 순차 신규 연결 재검증
- 실제 UID/GID, 파일 권한과 read-only mount

연결은 동시에 하나만 사용한다. password·pgpass·GSS·약한 TLS로 실패를 우회하지 않는다.
지원되는 psycopg는 3.2 이상, libpq는 안전한 취소를 지원하는 17 이상이어야 한다.
[Psycopg cancel_safe](https://www.psycopg.org/psycopg3/docs/api/connections.html#psycopg.Connection.cancel_safe),
[libpq 연결 옵션](https://www.postgresql.org/docs/18/libpq-connect.html)을 따른다.

입력 대기는 5초, 입력 검증 후 live CLI는 60초, Docker worker 호출은 25초로 제한한다.
worker의 DB 검사는 12초, worker 전체는 18초다. timeout 후 검사 container를 정리하며,
정리 실패와 실제 남은 resource를 확인하면 `RECOVERY_REQUIRED`를 반환한다.

## 결과와 오류

성공은 `status: succeeded`, exit 0이고 `checks`의 모든 항목이 `passed`다. `mode: live`,
`verification_scope: database-only`이며 target·연결·인증·인증서 항목만 실제 검증 결과를 반영한다.
`deployment`, source inventory/reader/admission, application readiness와 Query Man validation은
계속 `not_checked`다. 검사 container의 성공을 기존 application Pod의 검증으로 해석하지 않는다.

| 종료 코드 | 추가 오류 코드 |
|---|---|
| 6 | `AUTHORIZATION_REQUIRED` |
| 7 | `TARGET_MISMATCH`, `TARGET_DRIFT` |
| 8 | `EXECUTOR_FAILED`, `CREDENTIAL_ACCESS_DENIED`, `TLS_VERIFICATION_FAILED`, `CLIENT_AUTHENTICATION_FAILED`, `PERMISSION_DENIED`, `CONNECTION_FAILED`, `VERIFICATION_FAILED` |
| 9 | `RECOVERY_REQUIRED` |

timeout은 기존 exit 5다. worker가 실행되었다면 실패 시에도 각 검사의 passed/failed/not_checked를
반환한다. 접속 전 거절 또는 executor 자체의 실패는 빈 result를 반환한다. raw stderr, 내부 경로,
인증서 원문·DN·비밀번호·DSN은 결과에 반사하지 않는다.

## Disposable 검증

아래는 새 격리 network와 PostgreSQL container, 임시 PKI만 생성하는 opt-in 테스트다.
기존 DB/credential을 발견하거나 변경하지 않는다. 실행에 Docker와 로컬 `postgres:18.6-bookworm`,
`query-man:local` 이미지가 필요하며 각 fixture는 실제 image ID를 고정한다.

```bash
QUERY_PASSPORT_DOCKER_TESTS=1 uv run --locked pytest -q tests/test_live_integration.py
```

부정 검사는 별도 합성 credential과 격리 환경에서만 수행한다. 실제 설정 복구·발급·교체와
기존 voc-db 사용 전환은 M3 및 전환 검증의 완료 기준으로 별도 관리한다.
