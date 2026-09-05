# 개발 계획

Status: M1 구현 완료 / M2–M5 미구현

M1의 Python + uv package, `capabilities`·`inspect`·`plan`, JSON 입출력과 오프라인 검증을 구현했다.
M1 지원 계약은 [Tool contract](tool-contract.md)에 고정했고 M2 이후는 설계안이다.
실제 작업 경계는 [운영 설계](operations.md)가 소유한다.
문서를 작성했다는 이유로 외부 DB나 Kubernetes 실행이 승인되지는 않는다.

## 구현 순서

| 단계 | 목표 | 구현할 산출물 | 완료 기준 |
|---|---|---|---|
| M1 (완료) | 오프라인 계획을 스킬이 읽을 수 있게 만들기 | 단일 CLI/package, 요청 검증, version/capabilities, `plan` JSON, 사용 예시 | DB·Docker·PKI·Secret 접근 없이 정상/오류 결과를 예측 가능하게 반환 |
| M2 | 승인된 대상의 실제 연결 검증 | Docker 대상 확인, profile별 credential 전달 검증, live `verify`, 스킬의 최소 연계 | 정확한 대상에서 긍정/부정 접속 검사와 스킬 결과 해석이 재현됨 |
| M3 | 로컬 테스트 환경의 인증 준비 자동화 | 테스트 PKI 발급, 제한된 DB 인증 적용, 외부 상태 관리, 실패·재개·복구, DBA 스킬의 해당 호출 | 새 disposable DB에서 준비→검증→실패복구를 수행하고 기존 설정을 보존 |
| M4 | Pod에 credential을 공급하기 | 선택한 Secret provider 경로, manifest template, Pod UID/권한·DNS 검증, 별도 검증 Job | Pod 재생성·다른 node 배치 후에도 승인된 서비스 identity로 접속 |
| M5 | 갱신과 운영 인계 마무리 | rotation/폐기/복구 흐름, 만료 관리, consumer 호환 테스트, 운영 PKI·기록 체계 연계 | 새 인증서 전환과 장애 복구, 기록 보존, 전체 스킬 호출 계약을 환경별로 검증 |

M2부터 스킬 연계를 작게 검증한다. 모든 Kubernetes 기능이 생길 때까지 실제 consumer 연계를
미루지 않는다. 새 쓰기 기능은 해당 단계의 계약과 실행 검증이 갖춰진 뒤 스킬에 노출한다.

## 바로 이어서 할 첫 작업

1. M2를 시작할 때 승인된 disposable 대상·executor alias binding·읽기 전용 검증 범위를 고정한다.
2. 승인된 target과 endpoint·DB·환경·route가 일치하는지 실행 전에 확인하는 경계를 구현한다.
3. live `verify`에서 TLS·identity·인증서 거부·timeout·연결 복구를 검증한다.
4. Query Man 저장소의 지침에 따라 스킬의 capability 확인과 결과 해석을 별도 작업으로 연계한다.

M1에서 실제 환경은 접근하지 않았다. M2의 대상과 권한은 오프라인 요청의 alias나 digest로
증명되지 않는다. M1 계획을 실행 가능한 snapshot 또는 승인 artifact로 재사용하지 않는다.

## 단계별 상세 범위

### M1: 오프라인 계약

- 일반 hostname/port/database/profile 값과 환경·작업 scope를 구분한다. Profile ID와 PostgreSQL
  database 이름을 같은 것으로 취급하거나 입력 이름을 자동 교정하지 않는다.
- Query Man database profile v1의 `verify-full`/`client-certificate` 요구와 source v6 참조를
  보존한다. Passport가 source inventory나 전체 YAML validation의 새 authority가 되지 않는다.
- 스킬이 기존 Query Man 검증을 수행한 뒤 선택한 profile의 비밀 없는 입력을 전달하도록 한다.
  원본 revision/digest 결합이 필요한 쓰기 단계에는 다시 확인할 수 있는 artifact 참조를 붙인다.
- DB만 준비하는 입력에서 source 0개는 정상이다. DB/인증/배포 관측은 `not_checked`로 명시한다.
- Secret-store 식별자나 인증정보가 agent 입출력에 필요하지 않게 executor alias와 내부 binding을
  분리한다. 대상/명령 allowlist 검사를 두고 임의 shell·SQL 실행 기능은 제공하지 않는다.
- 요청/출력 크기, timeout, exit/result 계약과 known-error 분류를 정한다. 사람 설명과 JSON 결과가
  서로 다른 사실을 주장하지 않도록 한다.

M1 테스트는 정상 최소 요청, 필수값 누락, 잘못된 이름/port/version, 금지된 secret 필드, source 0개,
지원하지 않는 capability, 오프라인 경로의 network/credential 미접근과 결과 redaction을 포함한다.
입력 값을 그대로 오류에 반사해서 비밀이 노출되지 않는지 검증한다.

### M2: 읽기 전용 검사와 첫 스킬 연계

- 승인된 executor가 정확한 DB를 조사하고 host/port만으로 다른 환경을 대체하지 않도록 한다.
- `inspect`와 `plan`은 오프라인으로 유지한다. live 대상 조사와 인증서 metadata 검사는
  승인된 `verify` 경로에서 수행한다.
- Query Man과 같은 UID/GID, 파일 layout, read-only mount와 실제 DB driver 조건에서 검증한다.
- 정상 TLS/계정/DB/읽기 전용 transaction, 잘못된 서버 CA/hostname/client CA/DN/key, 인증서
  없음·만료·평문 거부, timeout/cancel/rollback 뒤 연결 복구를 확인한다.
- 부정 검사는 승인된 테스트 자격 증명과 범위에서만 수행한다. 정상 운영 계정의 동시 연결을
  고갈시키거나 업무 SQL/데이터를 읽는 방식으로 검사하지 않는다.
- 기존 source reader가 명시되었을 때만 reader별 권한·budget 검사 범위를 선택한다. 확인용
  계정의 성공에 source 검증 성공을 덧붙이지 않는다.
- Admin 스킬에는 offline `inspect`/`plan`, DBA onboarding 스킬에는 승인된 live `verify`를
  연결한다. 각 스킬이 tool version/capability를 확인하고 정제된 결과만 해석하도록 한다.
  Admin의 DB 직접 접속 금지를 CLI로 우회하거나 스킬이 private key를 열고 임의 psql 명령을
  조립하는 경로를 만들지 않는다.

Query Man 쪽 스킬 파일을 실제 변경할 때는 그 저장소에서 skill 개발 지침을 따르고, plan/execute
권한 경계를 보존하는지 함께 검증한다. 여기에 적은 목표만으로 현재 스킬을 변경했다고 간주하지 않는다.

### M3: 로컬 환경의 제한된 쓰기

- 먼저 **새 disposable fixture**에서 검증한다. 기존 voc-db는 회귀 대상 후보이며 자동 초기화
  대상이 아니다. Query Cave의 현재 lifecycle과 데이터를 임의로 바꾸지 않는다.
- 로컬 테스트 issuer와 운영 PKI의 경계를 구분한다. 테스트 키/인증서도 Git 밖에서 생성한다.
- 기존 승인된 reader 또는 명시적으로 요청한 제한된 확인 계정만 대상으로 한다. 업무 source,
  view, role 권한 정책을 추측하여 생성하지 않는다.
- plan에 대상 identity, 전후 변경, 기대 상태, 실행자, snapshot digest, 복구·stop 조건을 담는다.
- 이미 만족한 상태의 재실행, 계획 이후 drift, 동시 작업, 인증 실패, 일부 단계 실패와 도구
  종료 후 재개를 다룬다. 입력 hash가 같다는 이유만으로 현재 DB가 맞다고 판단하지 않는다.
- CA trust/HBA/ident를 적용 전에 검증하고 신규 계정의 로그인 허용 순서를 지킨다. reload 후
  실제 적용과 인증을 확인한다. 허용 범위를 넓혀 실패를 해결하지 않는다.
- rollback은 이번 작업이 소유한 변경만 대상으로 한다. 기존 role/DB 삭제나 나중에 바뀐 설정의
  전체 덮어쓰기를 자동 수행하지 않는다.

M3 완료는 “한 번 성공”이 아니라 실패 지점별로 기존 서비스·설정을 보존하거나 정확한 복구 필요
상태를 반환하는 것이다. 실행 사실과 복구 실패는 숨기지 않는다.

### M4: Kubernetes 전달

- 실제 사용할 cluster/context, namespace, workload와 Secret provider를 먼저 고정한다.
  해당 환경은 현재 조사·설정되지 않았다.
- 최소 한 경로를 end-to-end로 구현한다. Kubernetes Secret과 외부 Secret store 연동을 모두
  지원하기 위한 범용 provider framework를 먼저 만들지 않는다.
- repo에는 실제 Secret 값 없이 참조·mount·권한 template만 둔다. 앱에는 필요한 세 파일만
  전달하고 PKI authority와 운영 백업을 mount하지 않는다.
- Pod 재생성/재배치, app UID 읽기, 권한 없는 UID 접근 차단, 서버 DNS/SAN, DB egress 허용과
  인증서 mismatch를 검증한다. Node identity를 DB client identity로 사용하지 않는다.
- credential 전달 완료와 rollout/application acceptance를 별도 결과로 반환한다.

### M5: 갱신과 운영 인계

- 새 인증서 준비→신뢰 확인→새 instance 검증→전환→이전 인증서 정리 순서를 구현한다.
- 파일 갱신과 실제 connection pool 교체를 함께 확인한다. 같은 CA로 새 인증서를 발급해도
  이전 인증서가 자동 폐기되는 것은 아니다.
- 만료·폐기·키 유출 대응과 보통의 실패 rollback을 구분한다. CA trust 제거의 다른 사용자
  영향과 승인된 CRL/폐기 수단을 확인한다.
- protected 기록 시스템과 승인 수단을 실제 조직 환경에 연결한다. 예시 JSON이나 local file의
  `approved` 값으로 권한을 대신하지 않는다.
- tool/skill 호환성, output redaction, 제한된 실행 권한과 운영 문서를 같은 배포 단위로 검증한다.
- production 최초 활성화는 Query Man의 source·HTTP 인증·traffic-off acceptance 절차를 별도로
  따른다. Passport의 DB 검증 결과 하나로 launch 완료를 보고하지 않는다.

## 검증 책임과 완료 보고

M1 최소 환경은 Linux/POSIX, Python 3.12+, uv이며 현재 Python 3.12.3에서 검증했다.
런타임은 표준 라이브러리만 사용한다. `uv.lock`으로 개발 검사 의존성을 고정한다.

```bash
uv sync --locked
uv run --locked pytest -q
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy
uv build
```

2026-09-05 검증 결과: `pytest` 151개 통과, Ruff lint/format 검사 통과,
Mypy 소스 4개 파일 통과, wheel/sdist 빌드 통과. 별도 임시 virtualenv에 wheel을 설치해
`capabilities`·`inspect`·`plan` 진입점을 확인했다. 문서 JSON 예시와 실제 응답 일치,
workspace 문서 링크 24개를 확인했다. 기존 외부 저장소 참조 6개는 접근하지 않았다.
산출물 버전은 0.1.0이며 이 M1 검증 당시에는 Git 미초기화 상태라 commit revision이 없었다.

테스트는 root `tests/`에 있으며 schema·필수값·이름·port·version·금지 필드·source 0개,
미지원 명령/capability, JSON 크기·중첩·중복 key·UTF-8, symlink/hardlink/FIFO·workspace 경계,
입력값·예외 비노출, 네트워크·credential 미접근, stdin timeout과 출력 제한을 검증한다.
전체 Query Man YAML/source validator는 실행하지 않는다. 실제 인증서 거부·target drift·일부 적용
실패·복구는 아직 구현하지 않은 M2/M3의 검증이며 M1 통과로 대신하지 않는다. CI는 미구현이다.
M2부터 bounded integration, M3부터 failure/recovery, M4부터 container/Pod 검증을 추가한다.

구현 결과는 지원 capability, 아직 없는 기능, exact code/artifact revision, 수행한 검사와 실제 외부
실행 범위를 함께 보고한다. repository test 결과와 protected 운영 증빙은 각각의 저장소에서 관리한다.

## 실제 필요 시 결정할 항목

| 항목 | 결정 시점 |
|---|---|
| CLI 설치·배포 형식과 지원 Python version | M1 확정: Python 3.12+, uv, wheel/sdist, Linux/POSIX |
| 승인된 DB/PKI executor와 alias binding | 해당 외부 접근 기능을 시작하기 전 |
| Secret provider, namespace/workload와 app UID 정책 | M4 시작 전 |
| 발급기관, 인증서 수명·갱신 시점·폐기 방식 | 운영 PKI를 연결하기 전 |
| PgBouncer TLS 종단·pool mode, replica read-routing/failover | 별도 환경 요구가 들어온 뒤 |
| MCP transport 또는 상시 HTTP service | CLI로 충족되지 않는 실제 consumer 요구가 생긴 뒤 |

미정인 운영 환경 항목은 M1 개발을 막지 않는다. 뒤 단계의 미정 입력을 로컬 값으로 채워 운영 지원을
주장하지 않는다.
