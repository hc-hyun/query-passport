# 로컬 lifecycle 구현과 검증

0.3.0은 로컬 `prepare`, `issue`, `apply`, `deliver`, `rotate`, `rollback`, `status`를 제공한다.
이 문서는 operator 설정과 실행·복구 경계를 설명한다. 기존 voc-db 사용 전환, Kubernetes 전달과
인증서 폐기는 별도 검증·구현 대상이다.

## 구현 경로

`prepare`는 승인된 로컬 binding으로 대상과 설정을 조사하고, 기존 role과
PUBLIC의 실효 권한을 확인한다. 신규 확인 계정에 업무 객체 접근·schema 생성·TEMP 권한이
생기면 계획을 거절한다. 기존 grant를 자동 revoke하거나 DB·source·view·table을 만들지 않는다.
현재 backend는 PGDATA의 표준 HBA·ident·auto.conf 배치를 지원한다.

공개 요청과 달리 operator binding v2에는 고정한 container/image/network/UID, 관리자 socket과
PGDATA, 발급기관·발급 세대·서버 CA·credential 전달 위치가 들어간다. 이 설정은 기존
operator 전용 binding 디렉터리의 `0700`/`0600` 경계를 사용한다. 각 단계의 operation 권한을
따로 검사하며, `protected` 환경은 로컬 파일로 승인할 수 없다. 실제 경로는 스킬 JSON에 넣지 않는다.

계획은 target snapshot, 승인 범위 digest, 기존 설정과 credential revision을 결합하고 opaque
operation ID와 plan digest로 참조한다. 호출 때마다 요청·승인 범위·대상을 다시 확인한다.
승인 만료 시각만 연장한 동일 binding은 재사용할 수 있으며, 다른 대상·권한·경로로 변경하면
새 계획이 필요하다. M1의 `plan`은 계속 offline이며 이 실행 artifact를 대신하지 않는다.

1. `issue`: 별도 프로세스의 로컬 issuer가 CA와 credential 세대를 분리해 발급한다. 같은
   operation은 같은 발급 결과를 검증해 재사용한다. 불완전 파일이나 다른 입력은 덮어쓰지 않는다.
2. `apply`: 신규 확인 role을 `NOLOGIN`으로 만들고 기존 CA를 보존한 bundle, 소유한 HBA·ident
   구간과 auto.conf 구간을 적용한다. 설정 parser와 reload 관측을 확인한 뒤 로그인시킨다.
   적용한 CA bundle digest를 별도 배타적 receipt에 기록하고 이후 검사에서도 비교한다.
3. `deliver`: 새 immutable 버전 디렉터리에 세 파일만 전달한다. 별도 helper가 이 새 bundle에만
   UID/GID 권한을 설정한다. 실제 Query Man UID 10001의 읽기 전용 마운트에서 인증·TLS·취소·
   transaction 복구와 인증서 없음·평문 거부를 검사한 뒤 active pointer를 게시한다.
4. `rollback`: 이번 작업의 확인 role을 먼저 `NOLOGIN`으로 막고 소유한 설정 구간만 복구한다.
   이전 전달 revision으로 되돌리며 발급 세대·CA·비활성 role·복구 자료를 삭제하지 않는다.

최종 bundle의 파일명은 기존 `ca.crt`, `client.crt`, `client.key`다. Version 디렉터리는 실제
디렉터리이며, symlink로 기존 경로 검사를 우회하지 않는다. Binding v2의 `verify`는 private
active pointer가 선택한 버전을 target lock 안에서 읽고, 그 실제 디렉터리만 runtime에 mount한다.
CA private key나 복구 기록은 runtime에 전달하지 않는다.

## Operator v2 준비

[로컬 executor](local-executor.md)의 고정 OS 계정·binding 파일·대상 pinning 규칙을 그대로 적용한다.
`binding_version`을 `2`로 설정하고 기존 v1 필드에 다음 두 object를 추가한다. 이 파일은 operator가
기존 승인 범위로 작성하는 private 설정이며 공개 요청·CLI argument·환경변수에 넣지 않는다.

| 필드 | 필요한 값 |
|---|---|
| `operations` | 허용한 `prepare`, `issue`, `apply`, `deliver`, `rotate`, `rollback`, `status`, `verify`의 부분집합 |
| `credential_dir` | Passport가 소유할 새 전달 store 절대 경로. 기존 credential directory를 지정하지 않음 |
| `admin.uid`, `admin.gid` | 대상 container에서 승인된 PostgreSQL OS 계정의 양의 UID/GID |
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

각 명령의 종료 코드와 JSON 결과를 확인한 뒤 다음 명령을 실행한다. `issue`·`apply` 성공은
전달·인증 성공을 뜻하지 않는다. `deliver`는 새 프로세스에서의 실제 신규 연결과 거부 검증을
완료한 뒤에만 전환한다. 실패 시 자동으로 다음 단계에 진입하지 말고 같은 참조로 `status`를 조회한다.

갱신은 기본 요청에 `intent: rotate`를 넣은 별도 공개 `rotation-request.json`으로 prepare한 뒤,
같은 변환 절차로 `rotation-operation.json`을 만들고 다음 명령으로 수행한다.

```bash
query-passport prepare --request rotation-request.json > prepared.json
# 위 변환 코드에서 rotation-request.json과 rotation-operation.json을 사용한다.
query-passport rotate --request rotation-operation.json
query-passport rollback --request rotation-operation.json
query-passport rollback --request operation.json
```

Rotation은 같은 CA·서버 trust·확인 identity를 유지하고 새 키/인증서를 만든다. DB role·HBA·CA
설정을 다시 적용하지 않는다. 새 인증서 검증 실패 시 기존 active 버전이 유지된다. Rotation
rollback은 직전 세대의 실제 인증을 다시 검증한 뒤 pointer만 복구하므로 만료·인증 실패 세대로
되돌리지 않는다. 원본 DB 설정 rollback은 자식 rotation을 역순으로 복구한 뒤에만 가능하다.
발급·전달 세대는 보존하며 rollback으로 종료한 operation의 전진 실행은 거절한다.

같은 CA의 재발급은 이전 인증서를 폐기하지 않는다. CA 변경·CRL·기존 connection pool 종료·
앱 배포 전환은 이 명령의 지원 범위가 아니다. 마지막 `rollback`은 Passport 소유 확인 계정을
비활성화하고 설정을 복구하는 동작이므로 단순 상태 확인으로 실행하지 않는다.

## 기록·실패·복구

실행 기록은 OS 계정의 `~/.local/state/query-passport-executor/operations/`에 보관한다.
기존 인계·리뷰가 있는 `~/.local/state/query-passport/`는 읽거나 권한을 바꾸지 않는다. 공개 쓰기
CLI 이전 내부 API의 기록을 자동 이전하거나 다른 경로로 fallback하지 않는다. Operation과
server별 lock은 Passport 호출을 직렬화한다. 이 lock이 일반 DBA나 다른 도구의 실행까지
막는다고 가정하지 않는다.

상태 변경 전에 시작 이벤트를 추가하고, 완료 결과를 별도 기록한다. Timeout·중단은 외부
실행이 끝났다는 증거가 아니므로 `unknown`으로 남기고 다음 호출에서 현재 상태와 대조한다.
일부 쓰기나 기록 손상은 보존한 채 재조사를 요구한다. 같은 입력 hash만으로 적용 완료를
추정하거나 다음 단계를 진행하지 않는다.

설정 파일 교체는 실제 교체 대상 inode를 접근 제한된 backup에 보존한다. 새 파일 게시 시 다른
writer가 대상 경로를 만들었으면 덮어쓰지 않는다. 소유한 구간 밖의 변경은 복구 시 유지하고,
소유 구간 자체가 바뀌었으면 자동 복구를 중단한다. PostgreSQL 설정 파일 전체를 과거 백업으로
무조건 덮어쓰는 경로는 제공하지 않는다.

이 파일 시스템 기록은 로컬 복구용이며 protected immutable evidence가 아니다. `status`는
기록된 단계를 보여줄 뿐 새로운 접속·인증 검사 성공을 보고하지 않는다. 실제 DB 검증이 끝나도
source inventory·reader 권한·source admission·application readiness는 `not_checked`다.

## 재현 가능한 검사

최소 환경은 Linux/POSIX, Python 3.12+, uv, 로컬 Docker와 미리 준비된 PostgreSQL 18 및
Query Man runtime image다. 구체적인 image 전제는 [M2 executor](local-executor.md)를 따른다.

```bash
uv sync --locked
uv run --locked pytest -q
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy
QUERY_PASSPORT_DOCKER_TESTS=1 uv run --locked pytest -q tests/test_m3_fixture.py tests/test_m3_integration.py tests/test_installed_lifecycle.py --tb=short
```

Opt-in 검사는 새 내부 network·PostgreSQL·외부 `/var/tmp` PKI만 만들고 소유 label과 directory
identity를 확인해 자신이 만든 fixture만 정리한다. 기존 voc-db·호스트 자격 증명·백업을 검사
대상으로 선택하지 않는다. 실제 운영 자료를 이 fixture로 복사하지 않는다.

Query Man 스킬 consumer까지 연결하는 검사는 명시한 checkout의 DBA helper를 사용한다.
환경변수는 공개 코드 경로 선택용이며, 기본 테스트에서는 외부 저장소를 읽지 않고 건너뛴다.

```bash
QUERY_PASSPORT_DOCKER_TESTS=1 QUERY_PASSPORT_QUERY_MAN_REPO=/path/to/query-man uv run --locked pytest -q tests/test_skill_lifecycle.py --tb=short
```

검증 결과와 미완료 사항은 [개발 계획](development-plan.md#m3-진행-기록)에 기록한다.
