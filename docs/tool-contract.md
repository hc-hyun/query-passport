# Query Man 스킬과 Query Passport의 호출 계약

이 문서는 **0.4.0의 로컬 구현 계약과 이후 운영 설계안**을 구분한다. 계약 major 1의
오프라인 검사, 로컬 Docker 검증과 제한된 발급·적용·전달·교체 CLI를 구현했다.
Kubernetes 전달과 protected 승인 backend는 미구현이다.
현재 Query Man의 profile, 인증 단위, credential layout과 운영 승인을 변경하는 문서가 아니다.

## 1. 누가 무엇을 담당하는가

| 주체 | 책임 | 하지 않는 일 |
|---|---|---|
| Query Man 스킬 | 사용자 의도 파악, 비밀 없는 입력 수집, repo 변경·검증, 계획 설명, 승인 범위 확인, 결과 요약 | 개인 키 취급, 임의 관리자 접속, 출력만 보고 자동 재승인 |
| Query Passport CLI | 입력·대상 검증, 계획 생성, 실행 승인 검증, 제한된 동작 실행, 결과·오류 정규화 | 업무 SQL 생성, source 정책 변경, 범용 shell/SQL 실행 |
| 승인된 실행 backend | alias를 실제 접속·PKI·Secret 참조로 해석하고 필요한 권한 사용 | 실제 자격 증명이나 저장소 식별자를 agent에 반환 |
| DBA·PKI·배포 담당자 | 각 환경의 접근·변경 권한과 실행·복구 책임 제공 | 문서 작성 승인을 운영 실행 승인으로 간주 |
| Query Man 앱 | 전달된 profile·credential로 DB 접속, source 권한·SQL 안전 정책 강제 | 인증서 발급, DB 신뢰 설정 수정, CLI 런타임 호출 |

초기 전달 형태는 하나의 CLI와 JSON이다. Python API, HTTP service, MCP server를 동시에 만들지 않는다.
MCP는 실제 다중 클라이언트나 원격 실행 요구가 생긴 뒤 같은 검증·실행 경계를 감싸는 방식으로 검토한다.
Query Man 앱은 Query Passport 설치 여부에 런타임 의존하지 않는다.

기존 `query-man-admin` 스킬은 repo 작성과 읽기 전용 서버 점검을 맡는다. 이 스킬의 DB 직접 접속 금지를
CLI 호출로 우회하지 않는다. repo 전용 작업에는 offline `inspect`·`plan`만 연결하는 것이 첫 제안이다.
인증된 DB 검증과 실제 변경은 `query-man-dba-onboarding` 실행 절차에서 담당하도록 제안한다.
실제 스킬 수정은 해당 repo의 검토·승인 규칙을 따라 별도 변경한다.

## 2. 명령과 범위

모든 구현 명령의 기능은 `capabilities`와 도움말에 명시한다. 미구현 명령 실행 시
`UNSUPPORTED_OPERATION`을 반환한다. 같은 이름의 shell script로 대체 실행하지 않는다.

| 명령 | 개발 순서 | 허용 범위 |
|---|---|---|
| `capabilities` | 1 | 도구·계약 버전, 구현 기능, 지원 정책 확인. 환경·비밀 파일 접근 없음 |
| `inspect` | 1 | 호출자가 전달한 비밀 없는 profile 공개 필드의 정적 검사(repo 직접 읽기 없음). 네트워크·인증서 파일 접근 없음 |
| `plan` | 1 | 정적 검사 결과로 목표·차이·미확인 조건·필요 동작·검증·복구 계획 생성 |
| `verify` | 2 | 승인된 alias를 통한 live identity·TLS·기본 연결·읽기 전용 트랜잭션 검증 |
| `prepare` | 3 | 승인된 live snapshot과 변경·보존 항목을 고정하고 private operation 계획 생성 |
| `issue` | 3 | 로컬 issuer에서 계획된 확인 identity의 credential 세대 발급 |
| `apply` | 3 | 새 제한 확인 role, 기존 CA를 보존한 trust, 소유 HBA·ident 구간 적용 |
| `deliver` | 3 | 새 버전을 실제 인증·거부 검사한 뒤 private active pointer 전환 |
| `rotate` | 3 | 같은 CA·identity의 새 키/인증서 발급·신규 연결 검증 후 버전 전환 |
| `status` | 3 | 권한·대상과 결합된 operation의 마지막 기록 조회. 신규 DB 인증 검사는 아님 |

`verify`는 접속·bounded catalog 조회를 수행하므로 offline 검사가 아니다. 쓰기 방지와 timeout을 강제하고
승인된 진단 SQL만 실행한다. 역할 생성, HBA 수정, Secret 조회 덤프, 업무 행 조회를 포함하지 않는다.
PostgreSQL 18·UTF8, 실제 DB·로그인 identity, TLS·hostname 검증과 지정된 읽기 전용 세션을 구분해 확인한다.
읽기 전용 DB 검사도 연결 자원을 사용하며 실행 기록이 남는다. 새 사용자 승인 여부는 기존 세션의
승인된 환경·대상·범위를 먼저 확인하고 판단한다. protected 환경의 요구 사항은 [운영 설계](operations.md)를 따른다.

`plan`은 항상 offline이고 `executable: false`다. 로컬 쓰기의 실행 계획은 별도 `prepare`로
만들며, 반환한 operation 참조는 권한을 대신하지 않는다.

## 3. 입력과 실행 경계

스킬이 수집할 기본값은 profile ID, 접속 hostname, port, 실제 database 이름, 환경 구분,
deployment identity의 비밀 없는 이름, 이미 승인된 service alias다. 기존 값을 재사용하고 추측으로 채우지 않는다.
host와 database는 서로 다르며 profile ID가 실제 DB 이름을 대신하지 않는다.
source가 없는 요청은 `scope: database-only`, `source_count: 0`으로 명시한다.

`source_count`는 호출자가 제공한 문맥이며 Passport가 source inventory를 검증했다는 증거가 아니다.
오프라인 결과에는 `source_inventory: not_checked`를 함께 표시한다. 실제 inventory 확인은 기존
Query Man 검증이 담당하고, 실행 계획에 필요하면 그 결과의 revision과 현재 상태를 다시 대조한다.

입력 금지 항목은 password, token, 인증정보가 든 DSN, 인증서·개인 키 원문, 실제 Secret 내용,
Secret 저장소 식별자, 임의 credential 파일 경로다. 민감한 인증서 metadata도 일반 출력에 자동 포함하지 않는다.
agent는 예컨대 `local-voc-db-check` 같은 사전 승인된 비밀 없는 alias만 다룬다.
실제 provider 참조·key 위치·인증 세션은 실행 backend가 외부 설정과 승인된 권한으로 해석한다.
alias는 권한이 아니며 이름만 안다고 다른 환경을 실행할 수 없어야 한다.

CLI는 버전별 닫힌 JSON schema로 필수값·타입·길이·enum을 검증하고 미지 필드를 거절한다.
공개 입력 파일은 지정된 workspace의 일반 파일로 제한하고 파일 크기와 JSON nesting을 제한한다.
`inspect`는 credential directory를 재귀 탐색하지 않는다. schema 검증을 위해 `.env`나 전체 환경을 읽지 않는다.
비밀로 보이는 입력을 발견하면 원문·필드 값·주변 문맥을 출력하지 않고 분류 오류만 반환한다.

실행 backend에는 범용 command 문자열, shell template, SQL 문자열, plugin import path를 받는 입력이 없다.
PostgreSQL driver와 고정된 진단 statement를 사용하고 SQL identifier가 필요한 후속 작업은 별도 검증·인용한다.
공개 host 입력은 계획 자료일 뿐 live 접속 권한을 만들지 않는다. 실행 시 승인된 alias의 endpoint allowlist,
port·DB·환경·TLS 이름·route와 모두 일치해야 한다. 임의 URL·redirect·proxy·SSH 명령을 실행하지 않는다.
DNS, hostaddr, 포트 포워딩과 egress 경로 변경도 승인된 target binding과 비교해 임의 대상 접속을 차단한다.

## 4. M1 버전과 지원 기능 확인

아래는 **구현된 CLI 사용 예시**다. `request.json`은 비밀 없는 schema 입력이며 자격 증명 파일이 아니다.
명령 이름을 보고 구현 여부를 추정하지 않고 먼저 기능을 확인한다.

```bash
query-passport capabilities --format json
query-passport inspect --request request.json --format json
query-passport plan --request request.json --format json
```

유효한 로컬 operator binding이 준비된 실행 예시는
`query-passport verify --request request.json --format json`이다. CLI 플래그로 승인을 만들어 내지 않는다.

응답 envelope에는 `contract_version`, `tool_version`, `command`, `status`, `scope`, `result`, `errors`를 둔다.
capabilities 응답은 지원 contract major와 실제 구현된 기능 ID, backend 유형, 정책 revision을 제공한다.
기능 ID는 `profile.inspect.v1`, `plan.offline.v1`, `connection.verify.v2`, `lifecycle.local.v2`,
`credential.rotate.local.v2`이다. 정책 revision은 `mvp-local-lifecycle-2`이다.
스킬은 필요한 기능과 계약 major가 없으면 해당 작업을 중단하고 호환되는 도구 준비를 안내한다.
새 도구라고 가정해 알 수 없는 필드를 무시하거나 하위 버전으로 자동 실행하지 않는다.

초기 공개 입력의 **지원 예시**([파일](../examples/request.json)):

```json
{
  "contract_version": "1",
  "profile_version": 1,
  "scope": "database-only",
  "environment": "local-synthetic",
  "deployment_alias": "query-man-local",
  "target_alias": "synthetic-db-check",
  "profile": {
    "id": "example-db",
    "host": "db.example.test",
    "port": 5432,
    "database": "query_man",
    "sslmode": "verify-full",
    "authentication": {
      "type": "client-certificate"
    }
  },
  "source_count": 0
}
```

현재 Query Man profile version 1을 별도 계약으로 검증한다. Passport의 `contract_version`과 혼동하지 않는다.
profile 필드·source schema·credential layout을 바꾸지 않고 기존 validator의 적용 범위를 유지한다.

### M1 입력 규칙과 제한

[닫힌 JSON Schema](../schemas/request-v1.schema.json)는 공개 projection을 정의한다. 런타임의
표준 라이브러리 validator와 schema의 허용/거부 사례를 함께 테스트한다. 이것은 Query Man 전체
profile YAML/source v6 validator를 대체하지 않는다. `profile_validation: passed`의 범위는
`profile_validation_scope: public_projection_only`이며 `query_man_validation`은 `not_checked`다.

- 위 예시의 모든 필드는 필수다. 추가 허용 필드는 `required_capabilities`뿐이다. 모든 중첩 object에서
  미지 필드를 거절한다. `profile_version: 1`은 요청 envelope에 추가한 참조 버전이며 profile 원본의 변경이 아니다.
- `contract_version`은 문자열 `"1"`, `profile_version`은 정수 `1`이다. JSON의 실수 표기(`1.0`)와
  boolean은 정수 필드에서 거절한다(JSON Schema의 수학적 integer 판정보다 엄격한 wire 규칙).
- `scope`는 `database-only`, `environment`는 `local-synthetic`, `local`, `protected`만 받는다.
  환경 값과 alias의 구문 검사는 실제 대상 확인·allowlist binding·승인 검증이 아니다. Live 명령은
  별도 operator binding과 대상을 확인한다. [로컬 executor](local-executor.md)를 따른다.
- profile ID와 두 alias는 영문 소문자로 시작하는 소문자·숫자·단일 하이픈 구분 이름, 최대 63자다.
  database는 영문 또는 `_`로 시작하는 영문·숫자·`_`, 최대 63자이며 대소문자를 그대로 보존한다.
  이 제한은 M1 공개 projection의 지원 부분집합이며 기존 Query Man/PostgreSQL의 이름 규칙을 재정의하지 않는다.
- host는 ASCII hostname 또는 점으로 구분한 숫자 이름이며 전체 253자, 각 label 1–63자다.
  label의 처음/끝 하이픈, trailing dot, URL, DSN, IPv6, socket 경로는 지원하지 않는다. DNS 조회는 없다.
- port는 정수 1–65535, `source_count`는 정수 0–1000000이다. 양수도 caller 문맥으로만 보존하며
  reader 검사를 추가하지 않는다. TLS는 `verify-full`, 인증은 `client-certificate`만 허용한다.
- 선택적 `required_capabilities`는 중복 없는 최대 16개 기능 ID 배열이다. 위 capabilities의
  다섯 기능을 지원하며 미지원 기능 요구는 `UNSUPPORTED_OPERATION`이다.
- JSON은 UTF-8, 최대 65,536 bytes, 최대 깊이 8(root 깊이 1)이다. 중복 key, NaN/Infinity,
  여러 JSON 문서, 잘못된 UTF-8은 거절한다. stdout은 개행을 포함해 최대 16,384 bytes인 JSON 하나다.
- `--request FILE`은 `--workspace DIR`(기본 현재 디렉터리) 안의 상대 `.json` 일반 파일이다.
  절대 경로, `..`, 숨김 component, `credentials`·`authority`·`artifacts`·`probes`·`local` component,
  symlink 경유, hardlink, FIFO와 directory 입력은 거절한다. 파일은 공개 요청 전용으로 지정해야 한다.
  `--request -`는 stdin을 사용한다. JSON 내부의 파일/Secret 경로는 받거나 해석하지 않는다.
- 입력 대기를 포함한 오프라인 처리 제한은 고정 5초다. POSIX timer를 사용하며 timeout이면 exit 5다.
  프로세스 시작과 stdout 소비자의 대기는 처리 시간 밖이다. 호출자는 자체 프로세스 timeout도 적용한다.
- `--format json`은 생략 가능하며 유일한 출력 형식이다. `--help`, `--version`도 JSON envelope다.
  알 수 없는 CLI 인자·입력값·예외·경로는 stderr나 오류 메시지에 반사하지 않는다.

오프라인 성공 결과에는 자유형 입력 문자열을 복사하지 않고 정제된 count·고정 상태·digest만 반환한다.
`input_digest`는 검증한 입력을 key 정렬·공백 없는 ASCII JSON으로 직렬화한 SHA-256이다.
`plan_digest`는 그 입력 digest를 포함한 result에서 `plan_digest` 자체를 제외한 동일 형식의 SHA-256이다.
생략한 선택 필드와 명시한 빈 배열은 서로 다른 입력 digest를 가질 수 있다. digest는 외부 상태의
관측·승인·drift 검사 증거가 아니다. 저장된 계획이나 실행 handle도 발급하지 않는다.
M1의 `actions`는 빈 배열이며 후속 검증의 전제·중단 조건만 기술한다.

| 종료 코드 | 오류 코드 | 의미 |
|---|---|---|
| 0 | 없음 | `validated` 또는 `planned`, 요청된 오프라인 처리 완료 |
| 2 | `INVALID_INPUT`, `INPUT_TOO_LARGE` | 입력 schema/CLI/JSON 위반 또는 크기 초과 |
| 3 | `UNSUPPORTED_OPERATION`, `UNSUPPORTED_VERSION` | 미구현 명령·기능 또는 미지원 버전 |
| 4 | `INPUT_ACCESS_DENIED` | 공개 입력 파일 경계 위반 또는 읽기 불가 |
| 5 | `TIMEOUT` | 오프라인 처리 5초 초과 |
| 1 | `INTERNAL_ERROR`, `OUTPUT_TOO_LARGE` | 정제된 내부 실패 또는 출력 한도 초과 |
| 130 | `INTERRUPTED` | 처리 중 사용자 인터럽트 |

CLI·executor 예외의 `status`는 `failed`, `scope`는 `null`이다. `verify` worker가 반환한 실패는
`scope: database-only`와 검사별 결과를 유지한다. 오프라인·prepare·입력 검증 실패의 `result`는
빈 object이며, 유효한 후속 operation 요청의 오류에는 아래 작업 참조만 남긴다. 알 수 없는 명령 이름은
`command: null`로 반환한다. stdout 자체에 쓸 수 없으면 exit 1이며 JSON 전달을 보장할 수 없다.
스킬은 무응답·잘린 출력·비영 종료를 성공으로 취급하지 않는다.

## 5. 계획, 승인, 실행의 연결

### 구현된 로컬 lifecycle 요청

`prepare`는 기본 요청에 선택적 `intent: provision` 또는 `intent: rotate`를 받는다. 생략하면
`provision`이다. [Prepare schema](../schemas/prepare-request-v1.schema.json)를 따른다.
`issue`, `apply`, `deliver`, `rotate`, `status`는 기본 요청에
`operation: {id, plan_digest}`를 추가한다. `id`는 32자리 소문자 hex이고 `plan_digest`는
`sha256:`와 64자리 소문자 hex다. [Operation schema](../schemas/operation-request-v1.schema.json)를 따른다.
`verify`와 오프라인 명령에는 이 추가 필드를 허용하지 않는다.

`prepare` 결과는 `phase: prepared`, `intent`, `operation_id`, `plan_digest`, `mode: live`,
`source_count`, `target_identity: passed`, `recovery: not_supported`와 다음 검토 정보를 담는다.
`actions`와 `preserves`는 고정된 변경·보존 목록, `account`와 `client_dn`은 binding에서 검증한
확인 identity, `certificate_lifetime_days`는 승인된 최대 요청 수명(1–90일)이다. 실제 인증서
수명은 CA 만료일에 제한될 수 있다. 내부 경로·설정 원문·인증서 원문은 반환하지 않는다.

후속 성공 결과는 검토 정보를 제외한 같은 요약이다. `issue`는 `issued`, `apply`는 `applied`,
`deliver`·`rotate`는 새 연결 검증 후 `verified`다. Rollback은 지원하지 않는다.
`status`는 마지막 기록의 phase를 반환하지만 연결·인증·인증서 사실은 모두 `not_checked`다.
새 검증이 완료된 `deliver`·`rotate`만 세 사실을 `passed`로 반환한다. Source inventory,
reader 권한, source admission, deployment와 application readiness는 항상 `not_checked`다.

성공 envelope는 prepare `planned`, status `validated`, 나머지 `succeeded`다. 실패 envelope는
`failed`·`scope: null`이며 유효한 operation 요청에만 `operation_id`, `plan_digest`,
`outcome: not_confirmed`를 반환한다. 이 참조는
존재·권한·실제 phase를 확인했다는 뜻이 아니다. 실패 응답으로 완료 단계나 rollback 성공을 추정하지 않는다.
입력 검증 후 lifecycle 제한은 180초(`limits.lifecycle_timeout_seconds`)다. 스킬은 process 종료와
JSON·종료 코드 일치를 확인하고 충분한 bounded cleanup 여유를 둔다.

상세 operator v2 설정, 명령 예시와 재실행 방법는 [로컬 lifecycle](local-lifecycle.md)을 따른다.

## 6. 안전한 결과와 실패 의미

stdout은 제한된 크기의 JSON 하나이며 진행 알림과 stderr에도 원문 exception·provider 응답을 내보내지 않는다.
driver 오류, 연결 문자열, SQL literal, host 파일 경로, Secret 식별자, 인증서·키 원문은 정상·실패·debug 출력에서 제외한다.
로깅 전에 고정된 오류 코드로 정규화하며 출력 제한·redaction은 중첩 값과 오류 경로에도 적용한다.
민감한 상세 증거는 승인된 환경 기록 시스템에 남기고 agent에는 권한 검사 대상의 opaque artifact handle만 준다.

위 입력에 대한 M1 `plan`의 **실제 응답 예시**:

```json
{
  "contract_version": "1",
  "tool_version": "0.4.0",
  "command": "plan",
  "status": "planned",
  "scope": "database-only",
  "result": {
    "mode": "offline",
    "profile_count": 1,
    "source_count": 0,
    "profile_validation": "passed",
    "profile_validation_scope": "public_projection_only",
    "source_inventory": "not_checked",
    "query_man_validation": "not_checked",
    "target_identity": "not_checked",
    "db_connectivity": "not_checked",
    "certificate_validation": "not_checked",
    "authentication": "not_checked",
    "deployment": "not_checked",
    "reader_permissions": "not_checked",
    "source_admission": "not_checked",
    "application_readiness": "not_checked",
    "input_digest": "sha256:40c2720bcd45e015b21194cd5fc3c679836fa5651a0e9d2c34872966778865cb",
    "policy_revision": "mvp-local-lifecycle-2",
    "executable": false,
    "target_snapshot": "unknown",
    "differences": "unknown",
    "actions": [],
    "desired_state": {
      "sslmode": "verify-full",
      "authentication": "client-certificate"
    },
    "required_capabilities": [
      "connection.verify.v2"
    ],
    "next_action": "authorized_read_only_verification",
    "preconditions": [
      "query_man_profile_validation",
      "authorized_executor_target_binding",
      "live_target_snapshot"
    ],
    "verification": [
      "target_identity",
      "db_connectivity",
      "certificate_validation",
      "authentication",
      "deployment"
    ],
    "stop_conditions": [
      "unsupported_capability",
      "missing_authorization",
      "target_mismatch"
    ],
    "recovery": "no_changes_performed",
    "plan_digest": "sha256:a188f5b942c6bdb274cec3f8a723ddbb5bf856800ac2ae2cc01c8a207dca1981"
  },
  "errors": []
}
```

구현된 envelope `status`는 `validated`, `planned`, `succeeded`, `failed`다.
실패는 추가 journal 상태를 만들지 않으며 마지막 시작·완료 기록을 보존한다.
`succeeded`는 요청된 scope의 검증 완료만 뜻한다. 검사 항목은 `passed`·`failed`·`not_checked`를 별도 표시한다.
정상 종료 코드는 0이며 오프라인은 `validated`·`planned`, live 검증 완료는 `succeeded`다.
실패는 `failed`와 비영 종료를 반환한다. 종료 코드 6–9 및 live 결과는 [로컬 executor 계약](local-executor.md)에 있다.
스킬은 종료 코드뿐 아니라 JSON schema·status·검사 항목을 확인하며 알 수 없는 응답은 성공으로 보고하지 않는다.

오류 예시는 `INVALID_INPUT`, `UNSUPPORTED_OPERATION`, `AUTHORIZATION_REQUIRED`, `TARGET_DRIFT`,
`TLS_VERIFICATION_FAILED`, `CLIENT_AUTHENTICATION_FAILED`, `PERMISSION_DENIED`, `TIMEOUT`,
`PKI_PARTIAL_STATE`, `DELIVERY_PARTIAL_STATE`, `DB_CONFIG_WRITE_FAILED`, `STATE_WRITE_FAILED`다. 메시지는 고정된 설명과 안전한 다음 동작만 포함한다.
원문 stderr를 보여 주기 위해 재실행하거나 약한 TLS·비밀번호·추가 grant로 우회하지 않는다.

## 7. 오류와 재실행

명령은 한 번 실행한다. 실패 시 원래의 고정 오류 코드와 비영 종료를 반환하며 자동 보상 변경·rollback은 없다.
같은 operation ID로 재실행할 수 있다. 완료 자료는 동일성을 확인하고 재사용하며 중간 파일과 drift는 오류다.
실패 result는 검증된 `operation_id`, `plan_digest`, `outcome: not_confirmed`만 포함한다.
오류 원문이나 추측한 완료 단계·다음 복구 동작을 포함하지 않는다. `status`도 fresh 검증이 아니다.

0.4.0 live capability는 v2다. 0.3.0 consumer/작업 계획/전달 store의 자동 호환은 제공하지 않는다.
M1 JSON envelope major 1과 오프라인 capability는 유지한다. 전체 고정 오류 코드는
[src/query_passport/contract.py](../src/query_passport/contract.py)의 `ERRORS`가 정의한다.

## 8. 첫 구현의 완료 기준

M1은 네트워크 없이 위 입력을 `inspect → plan`으로 처리한다. schema·capabilities·safe JSON,
잘못된 입력·비밀 필드 비노출·source 0개의 의미를 root `tests/`에서 검증했다. live 성공을 주장하지 않는다.
M2의 실제 `verify`는 별도 승인된 local alias와 disposable fixture로 검증한다. 성공·인증서 거부·실행 timeout
결과를 정규화하고, target mismatch와 미승인 접속이 실행 전에 거절됨을 검증한다.
로컬 스크립트를 감싸 raw 출력만 넘기는 구현은 이 계약을 만족하지 않는다.

profile 1개·source 0개는 등록 단계에서 유효하다. 기존 Query Man runtime의 source 0개 거부는 유지한다.
이 경우 기존 repo inventory test 경로를 사용하며 source-package helper를 통과시키려고 dummy source를 넣지 않는다.
DB 연결 검증 성공은 reader 권한·source admission·API readiness·업무 조회 성공을 증명하지 않는다.
구현 단계와 이후 PKI·배포 작업은 [개발 계획](development-plan.md), 기존 자료는 [로컬 인계](local-handoff.md)를 따른다.
