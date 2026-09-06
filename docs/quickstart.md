# 가끔 사용하는 운영자를 위한 사용 안내

Query Passport 0.4.0 / Linux·Python 3.12+·uv 기준이다. 실제 접속·발급은 승인된 로컬 Docker와
PostgreSQL 18/UTF8, 준비된 runtime image가 필요하다. 실제 경로·대상·만료일은 환경별 운영 인계를 따른다.

## 1. 설치와 버전 확인

검증한 wheel을 지정해 설치한다. 임시 빌드 폴더나 editable checkout에 의존하지 않는다.

```bash
uv tool install /path/to/approved/query_passport-0.4.0-py3-none-any.whl
query-passport --version
query-passport capabilities
```

기존 설치를 갱신한다면 같은 wheel을 지정해 `uv tool install --force`로 교체한다.
버전 명령도 JSON이다. `tool_version: 0.4.0`, live capability의 `connection.verify.v2`,
`lifecycle.local.v2`, `credential.rotate.local.v2`를 확인한다. Query Man 호출부도 0.4.0 대응 버전이어야 한다.

## 2. 처음 한 번 준비할 설정

- 공개 `request.json`: Query Man에서 검증한 profile의 공개 필드만 사용한다.
  [요청 예시](../examples/request.json)를 참고하고 `source_count: 0`을 그대로 허용한다.
- 비공개 operator binding: 실행 OS 계정 홈의
  `~/.config/query-passport/executors/<target_alias>.json`에 둔다. `HOME` 변경으로 위치를 바꾸지 않는다.
- [전체 binding 예시](../examples/operator-binding.example.json)는 합성 대상이며 `expires_at: 0`으로
  비활성화되어 있다. 실제 승인된 UID·container/image/network ID·시작 시각·DB 계정·경로·만료를 모두
  확인해 작성한다. `request`에는 승인한 공개 요청을 넣는다. 샘플을 그대로 설치하지 않는다.
  CA 생성과 확인 계정 준비가 승인된 경우에만 예시의 두 `allow_*` 설정을 사용한다.
- Binding directory는 실행 계정 또는 root 소유 `0700`, 파일은 같은 소유 조건의 `0600` 일반 파일이다.
  상위 경로도 신뢰한 계정 소유이며 group/other 쓰기가 없어야 한다. Symlink는 허용하지 않는다.
- CA·발급 세대·전달 경로는 Git 밖에 서로 분리한다. 도구가 관리할 경로는 새 전용 위치를 사용한다.
  CA 및 private 관리 폴더는 실행 계정 소유 `0700`, private 파일은 `0600`으로 준비한다.
  기존 공유 상위 폴더가 `0775`라면 하위 폴더만 `0700`으로 바꿔도 해결되지 않는다.
  기존 공유 폴더나 인증서를 일괄 chmod/chown하지 말고 승인된 전용 경로를 준비한다.

파일 내용을 출력하지 않고 `stat` 등으로 소유자·권한과 상위 경로를 확인한다. Binding·키·인증서
원문을 Git·채팅·일반 로그에 넣지 않는다. 기존 호스트 UID 소유 credential을 그대로 쓰면 거절될 수 있다.
최종 bundle은 root 또는 runtime UID(10001) 소유여야 한다. 키는 runtime UID의 `0600` 또는
root:10001의 `0640`이어야 하며, 호출자와 runtime이 필요한 디렉터리에 접근 가능해야 한다.
새 bundle 권한은 `deliver`가 설정한다. 상세 필드와 monitoring 예외는 [로컬 lifecycle](local-lifecycle.md#operator-v2-준비)을 따른다.

## 3. 발급 또는 갱신

작업마다 별도 공개 요청·결과 폴더를 만들고 그 안에서 실행한다. 기존 결과를 덮어쓰지 않는다.
먼저 DB를 변경하지 않는 입력 검사를 한다.

```bash
query-passport inspect --request request.json
query-passport plan --request request.json
```

두 명령은 오프라인이다. `planned`가 실제 접속·인증서 검증을 뜻하지 않는다.
신규 확인 계정과 인증 설정을 준비할 때만 다음 live 계획을 만든다.

```bash
query-passport prepare --request request.json > prepared.json
```

계획의 account·client DN·actions·preserves를 확인한 뒤 작업 참조를 보관한다.
다음 변환은 성공한 계획만 사용하며 비밀 파일을 읽지 않는다.

```bash
python3 - <<'PY_REQUEST'
import json
from pathlib import Path
request = json.loads(Path("request.json").read_text())
prepared = json.loads(Path("prepared.json").read_text())
assert prepared["status"] == "planned" and not prepared["errors"]
request["operation"] = {
    "id": prepared["result"]["operation_id"],
    "plan_digest": prepared["result"]["plan_digest"],
}
Path("operation.json").write_text(json.dumps(request) + "\n")
PY_REQUEST
```

신규 발급은 순서대로 실행한다. 실패하면 다음 명령으로 넘어가지 않는다.

```bash
query-passport issue --request operation.json > issue-result.json &&
query-passport apply --request operation.json > apply-result.json &&
query-passport deliver --request operation.json > deliver-result.json &&
query-passport verify --request request.json > verify-result.json
```

**갱신은 새 작업 폴더에서** 같은 기본 `request.json`을 사용한다. 별도 `rotation-request.json`은
기본 요청에 `"intent": "rotate"`만 추가해 만든다.

```bash
query-passport prepare --request rotation-request.json > prepared.json
```

위 Python 변환으로 새 `operation.json`을 만든 뒤 실행한다. 갱신에 `apply`를 다시 호출하지 않는다.

```bash
query-passport rotate --request operation.json > rotate-result.json &&
query-passport verify --request request.json > verify-result.json
```

`prepared.json`, `operation.json`, 정제된 결과와 각 종료 코드를 작업 인계에 남긴다.
같은 작업을 재실행할 때 결과는 새 파일명으로 보관해 이전 실패 이력을 덮어쓰지 않는다.
도구의 private 계획·실행 이력은 `~/.local/state/query-passport-executor/operations/`에 보존된다.

## 4. 앱에 사용할 인증서

운영자는 승인된 전달 경로의 활성 세대를 확인해 `<credential_dir>/versions/<generation_id>/bundle`을
앱의 `/run/secrets/query-man/databases/<profile.id>/`에 읽기 전용으로 마운트한다.
Bundle에는 `ca.crt`, `client.crt`, `client.key`만 들어간다. 실제 경로는 환경별 인계 문서에 남긴다.

**갱신은 앱 mount·Pod·connection pool을 자동 교체하지 않는다.** 실제 사용할 때 새 세대를 연결하고
앱의 새 연결을 검증한다. Source 0개인 확인 계정의 접속 성공은 source/reader·앱 readiness 성공이 아니다.

## 5. 오류가 나면

| 오류·상황 | 다음 동작 |
|---|---|
| `AUTHORIZATION_REQUIRED` | 실행 계정, binding 위치·권한·승인 만료를 확인. 동일 범위라면 수정 후 같은 명령 재실행 |
| `OPERATION_BUSY`, `DELIVERY_BUSY`, 일시적 연결 실패 | 다른 실행 종료 또는 연결 원인을 확인한 뒤 같은 명령·operation 참조로 재실행 |
| `CREDENTIAL_ACCESS_DENIED`, `DELIVERY_PERMISSION_DENIED`, `PKI_ACCESS_DENIED`, `STATE_ACCESS_DENIED` | 소유자·파일/상위 경로 권한 확인. 기존 credential의 무조건 chown이나 권한 완화로 우회하지 않음 |
| `TIMEOUT`, `INTERRUPTED`, 쓰기 실패 | 이미 일부 적용됐을 수 있음. `status`와 현재 파일·DB 상태를 확인하고 원인 해결 후 같은 작업으로 재실행 |
| `TARGET_DRIFT`, `DELIVERY_DRIFT`, 입력 충돌 | 중단하고 승인한 대상·계획과 현재 상태를 대조. 일부 적용 중이면 무조건 새 prepare로 우회하지 않음 |
| `PKI_PARTIAL_STATE`, `DELIVERY_PARTIAL_STATE`, `STATE_PARTIAL` | 불완전한 파일·기록 확인을 위해 중단. 단순 재실행으로 복구되지 않을 수 있음. 자동 삭제·덮어쓰기 금지 |
| TLS·클라이언트 인증 실패 | CA·이름·identity·인증서 만료 확인. 약한 TLS나 password fallback으로 우회하지 않음 |

```bash
query-passport status --request operation.json
```

`status`는 마지막 기록이다. `phase: verified`도 **현재 접속 성공**의 증명이 아니다.
현재 접속은 `verify`로 확인한다. 자동 재시도·보상 변경·rollback은 없다.

## 6. 두 만료를 구분하기

- **실행 승인 만료:** binding의 `expires_at`(UTC Unix 초). 운영자가 동일 대상·권한을 재확인한 뒤
  이 시각만 연장하면 기존 작업 참조를 유지할 수 있다. 만료 자체가 DB 인증서를 폐기하지는 않는다.
- **인증서 만료:** 발급된 client 인증서의 유효기간. 승인 연장으로 늘어나지 않는다. 만료 전에
  `prepare(intent: rotate)`→`rotate`하고 앱에서 사용할 새 세대도 연결한다. CA 만료는 별도 PKI 조치가 필요하다.

DB 재시작·대상·경로·identity 변경으로 생긴 drift를 승인 만료 연장으로 우회하지 않는다.
새 인증서 발급도 이전 인증서 폐기를 뜻하지 않는다. 만료일과 다음 사용 시 확인할 위치를 환경 인계에 기록한다.
