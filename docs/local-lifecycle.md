# 로컬 lifecycle

0.4.0 MVP는 발급·DB 인증 적용·검증 후 전달·같은 CA의 갱신을 제공한다.
실패하면 즉시 오류를 반환하며 자동 복구나 rollback 명령은 제공하지 않는다.
설치부터 다시 확인할 때는 [짧은 사용 안내](quickstart.md)를 먼저 읽는다.

## 기본 흐름

1. `prepare`: 승인된 대상과 현재 DB 설정·권한을 확인하고 private 계획을 저장한다.
2. `issue`: 별도 issuer 프로세스가 로컬 CA 및 client 인증서를 준비한다.
3. `apply`: 새 확인 계정을 NOLOGIN으로 만들고 기존 CA·HBA·ident를 보존하며 인증 규칙을 추가한다.
   Reload와 설정 검사가 완료된 후 LOGIN으로 전환한다.
4. `deliver`: 새 버전 디렉터리에 `ca.crt`, `client.crt`, `client.key`를 전달한다.
   실제 runtime UID로 정상 인증, 인증서 없음·평문 거부, 다시 정상 인증을 확인한 뒤 active pointer를 바꾼다.
5. `verify`: 활성 세대로 새 DB 연결을 확인한다. Source와 앱 readiness는 검사하지 않는다.

`rotate`는 새 키와 인증서를 발급·검증·전달한다. 기존 CA와 DB 설정은 변경하지 않는다.
이전 세대는 보존하지만 자동 되돌리기와 폐기는 지원하지 않는다. 앱의 mount/rollout은 별도 작업이다.

## Operator v2 준비

[로컬 executor](local-executor.md)의 고정 OS 계정·binding 파일·대상 pinning 규칙을 그대로 적용한다.
`binding_version`을 `2`로 설정하고 기존 v1 필드에 다음 두 object를 추가한다. 이 파일은 operator가
기존 승인 범위로 작성하는 private 설정이며 공개 요청·CLI argument·환경변수에 넣지 않는다.

| 필드 | 필요한 값 |
|---|---|
| `operations` | 허용한 `prepare`, `issue`, `apply`, `deliver`, `rotate`, `status`, `verify`의 부분집합 |
| `credential_dir` | Passport가 소유할 새 전달 store 절대 경로. 기존 credential directory를 지정하지 않음 |
| `admin.uid`, `admin.gid` | 대상 container에서 승인된 PostgreSQL OS 계정의 양의 UID/GID |
| `admin.monitoring` | 선택적 `pg_stat_statements` 1.12의 승인된 catalog digest. 기본값은 예외 없음 |
| `admin.username` | 선택적 관리자 DB role. 생략하면 `postgres`; OS 사용자명과 다를 수 있음 |
| `admin.socket_directory` | `/var/run/postgresql` |
| `admin.pgdata` | 대상의 실제 PGDATA 절대 경로. HBA·ident·auto.conf는 표준 PGDATA 배치 |
| `admin.network_cidr` | pinning한 hostaddr를 포함하는 승인된 IPv4 network, `/16` 이상으로 제한 |
| `admin.connection_limit` | 정수 `2` |
| `lifecycle.authority_dir` | 외부 private `0700` CA directory. Git 밖에 위치 |
| `lifecycle.authority_id` | 승인된 발급기관의 소문자 alias, 최대 63자 |
| `lifecycle.generations_dir` | CA와 분리된 외부 private 발급 세대 경로 |
| `lifecycle.server_ca_file` | 승인된 서버 CA bundle의 외부 일반 파일 경로 |
| `lifecycle.lifetime_days` | 1–90일의 요청 수명 |
| `lifecycle.allow_initialize_authority` | 새 로컬 CA 생성이 승인되었을 때만 `true`, 아니면 기존 관리 CA 필요 |
| `lifecycle.allow_create_check_role` | 제한 확인 계정의 준비 범위는 `true` 필요 |

CA·발급 세대·전달 store 경로는 서로 같거나 중첩될 수 없다. 서버 CA는 이 세 경로 밖에 둔다.
관리자 DB role은 기존 승인된 계정을 명시하며 현재 사용자·세션 사용자·superuser 여부를 확인한다.
이 이름은 새 확인 계정인 최상위 `username`과 별개이고 실제 인증 수단을 대신하지 않는다.
Symlink·넓은 쓰기 권한·Git ancestor를 거절한다. 기존 비밀 파일을 찾아 복사하거나 비밀번호로
접속해 설정을 우회하지 않는다. `prepare`의 `intent: provision`은 새 role이 없고 PUBLIC에서 업무 접근·CREATE·TEMP가
상속되지 않는지 검사하며 불일치를 거절한다. 기존 role을 자동 인수하거나 권한을 revoke하지 않는다.

`deliver`에는 `verify`, `rotate`에는 `issue`·`deliver`·`verify` 권한도 필요하다. 승인 갱신은
동일 binding의 `expires_at`만 연장할 수 있다. 대상·경로·허용 operation·identity 변경은 기존
계획을 무효화한다. 앱은 Passport의 active pointer를 읽지 않는다. 앱 mount/rollout이 필요한
경우 별도 승인된 배포 절차에서 검증한 실제 bundle 디렉터리를 사용해야 한다.

## CLI 실행 예시

먼저 기존 Query Man validator로 확인한 공개 요청 `request.json`과 operator binding을 준비한다.
아래는 해당 범위가 승인된 뒤 실행하는 예시이며, 저장하는 파일은 비밀 없는 요청과 정제된 응답이다.
`prepare` 자체는 live 조회와 새 operation 기록을 만들고 DB·인증서 변경은 하지 않는다.

```bash
query-passport capabilities
query-passport prepare --request request.json > prepared.json
```

`prepared.json`의 account·client DN·actions·preserves를 검토하고 반환된 참조를 같은 요청에 결합한다.
다음 코드는 성공한 prepare만 후속 요청으로 변환하며 인증서·binding을 읽지 않는다.

```bash
python3 - <<'PY_REQUEST'
import json
from pathlib import Path
request = json.loads(Path("request.json").read_text())
prepared = json.loads(Path("prepared.json").read_text())
assert prepared["status"] == "planned" and not prepared["errors"]
request.pop("intent", None)
request["operation"] = {
    "id": prepared["result"]["operation_id"],
    "plan_digest": prepared["result"]["plan_digest"],
}
Path("operation.json").write_text(json.dumps(request) + "\n")
PY_REQUEST
query-passport issue --request operation.json
query-passport apply --request operation.json
query-passport deliver --request operation.json
query-passport verify --request request.json
query-passport status --request operation.json
```


명령 하나가 실패하면 다음 단계로 넘어가지 않는다. 원인을 해결한 뒤 동일 `operation.json`으로
실패한 명령을 재실행한다. 발급 및 전달이 이미 완료되었으면 같은 입력·파일인지 확인하고 재사용한다.

갱신은 기본 요청에 `intent: rotate`를 추가한 `rotation-request.json`을 prepare하고,
위 변환 코드로 `rotation-operation.json`을 만든 후 실행한다.

```bash
query-passport prepare --request rotation-request.json > prepared.json
# 위 변환 코드에서 rotation-request.json과 rotation-operation.json을 사용한다.
query-passport rotate --request rotation-operation.json
```

## 오류와 재실행

- 오류의 원문·인증서·키·private 경로는 출력하지 않는다. PKI/전달/기록 오류는 구체적인 고정 코드로 반환한다.
- 오류를 잡아 DB를 추가 변경하거나 실패 기록을 쓰지 않는다. 최초 오류를 그대로 반환한다.
- 작업 시작·완료 기록과 계획·발급·적용·전달 결과는 재실행의 동일성 확인에 사용한다.
- `status`는 마지막 기록이다. 시작 기록만 있으면 외부 변경의 완료 여부를 의미하지 않는다.
  기록상 `verified`여도 접속·인증·인증서 검사는 `not_checked`로 표시한다.
- Timeout은 변경 취소를 뜻하지 않는다. 같은 참조로 재실행하면 현재 상태를 확인한다.
- 중간 파일이 불완전하면 `PKI_PARTIAL_STATE`, `DELIVERY_PARTIAL_STATE`, `STATE_PARTIAL` 등으로 중단한다.
  파일을 지우거나 덮어쓰는 자동 수선은 없다. 대상 drift도 자동으로 받아들이지 않는다.
- 계획 형식은 v2이고 전달 store owner는 `query-passport-credential-delivery-v2`다.
  0.3.0 계획·전달 store의 자동 재개·마이그레이션은 지원하지 않으며 기존 자료는 보존한다.

작업 기록은 OS 계정의 `~/.local/state/query-passport-executor/operations`에 둔다.
로컬 기록은 protected immutable evidence가 아니다. CA key는 외부 private 발급 경계에 남는다.

## 테스트

기본 검사는 DB 없이 실행한다. 실제 검사는 새 disposable PostgreSQL과 전용 PKI만 사용한다.

```bash
uv run --locked pytest -q
QUERY_PASSPORT_DOCKER_TESTS=1 uv run --locked pytest -q --tb=short
```

[개발 계획](development-plan.md)에 현재 검증 결과를 기록한다.
