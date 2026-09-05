# 기존 로컬 작업 인계

이 문서는 Query Passport 개발에서 참고할 **기존 로컬 voc-db 작업물의 위치와 한계**를 설명한다.
현재 목표는 그 도구를 일반화하는 것이며, 이 문서가 기존 DB 변경·파일 이관·삭제를 지시하지 않는다.
로컬 개발 기록은 사내 protected 환경의 실행 승인이나 운영 증빙이 아니다.

## Query Man 저장소

- 경로: `/home/hchyun/works/query-boy` (제품명 Query Man)
- 문서 작성 시 확인한 HEAD: `85b0927f2ea2b52ec2814398ef66440d287684af`
- 위 HEAD 이후의 DB 등록·스킬 보완은 아직 working tree에 있다. HEAD만 checkout하면 그 변경이
  없을 수 있으므로 인계 이후 실제 `git status`와 diff를 다시 확인한다.
- 변경 파일: `config/database-profiles.yaml` 신규, 두 repository skill과 `docs/skills.md`,
  `docs/development-todo.md` 수정. 앱 Python 코드나 production source는 추가하지 않았다.
- Query Passport 문서를 작성하는 동안에는 그 저장소를 변경하지 않았다.

기존 계약과 검증의 authority는 [Query Man 문서 안내](../../query-boy/docs/README.md),
[ADR 0036](../../query-boy/docs/decisions/0036-database-profile-client-certificate.md),
[인증서 가이드](../../query-boy/docs/database-certificate-authentication.md)다.
스킬은 [Admin](../../query-boy/.agents/skills/query-man-admin/SKILL.md)과
[DBA onboarding](../../query-boy/.agents/skills/query-man-dba-onboarding/SKILL.md)을 읽는다.
이 인계 문서 작성 시점에는 설치 가능한 `query-passport` tool과 그 호출이 없었다.
현재는 M1 오프라인 CLI와 M2 로컬 접속 검증·Query Man 스킬 연계를 구현했다.
이 문서의 기존 호스트 작업물과 실제 voc-db 사용 전환은 아직 수행하지 않았다.

## 로컬 DB 상태

| 항목 | 현재 로컬 작업에서 사용한 값 |
|---|---|
| Container / profile ID | `voc-db` |
| 실제 PostgreSQL database | `query_man` |
| 서버 | PostgreSQL 18.6, UTF8, primary |
| Docker 접속 | `query-man_default` network의 `voc-db:5432` |
| Host 접속 | `127.0.0.1:5678` |
| 연결 확인 계정 | `query_man_voc_db_check` |
| 클라이언트 DN | RFC 2253 기준 `CN=query-man-voc-db` |
| 클라이언트 인증서 만료 | 2026-12-04 11:27:33 KST |
| Source | 0개. 업무 source/reader/view 준비는 미착수 |

이 값은 새 환경의 default가 아니다. 재사용 전 대상·version·유효기간을 다시 확인해야 한다.
`voc-db`는 profile/container 이름이고 `query_man`은 실제 DB 이름이다. 같은 서버에 있는
`market_voc`, `development_issues`를 profile 대상으로 자동 치환하지 않는다.

확인 계정은 비밀번호 없이 제한된 인증서 mapping으로 로그인한다. Privileged role이나 membership은
없고 connection limit 2, 기본 read-only, statement timeout 2초를 적용했다. 이 계정은 실제 source
reader가 아니며 source의 전체 budget/parameter SET 권한이나 metadata admission을 증명하지 않는다.
`default_transaction_read_only`는 변경 가능한 기본값이므로 권한 제한과 runtime transaction 강제를
대신하는 불변의 쓰기 방지 수단으로 설명하지 않는다.

## 호스트 작업물

전체 위치: `/home/hchyun/.local/state/query-man/voc-db/`

| 경로 | 내용 | Query Passport로 가져오는 방법 |
|---|---|---|
| `README.md` | 접속·검증·복구 안내 | 범용 문서 작성의 참고 자료로 사용 |
| `check_connection.py` | 같은 app UID로 실행하는 실제 접속/실패 조건 검증 | 비밀 없는 코드를 검토해 일반화; 환경 고정값 분리 |
| `runtime.env` | 호스트·port·mount 위치 | 실제 파일을 template로 오인하지 말고 값 없는 예시로 재작성 |
| `credentials/voc-db/` | `ca.crt`, `client.crt`, `client.key` | repo로 복사하지 않음; 향후 승인된 Secret 전달 체계로 이관 |
| `authority/` | 로컬 client CA key/cert, 테스트 CA와 발급 중간 자료 | repo로 복사하지 않음; PKI 관리자 영역 |
| `server/` | 기존 server CA 사본, client CA bundle | 실제 파일은 외부 보관; 필요한 구조만 template로 작성 |
| `probes/` | 만료·미신뢰·미매핑 인증서와 키 | fixture 생성 로직만 개발하고 test material은 외부에서 생성 |
| `operations/apply-tls.py` | 당시 설정에 맞춘 적용·복구 도구 | 변경 소유권·drift·복구 범위를 재설계한 뒤 재사용 |
| `operations/*.before`, `*.proposed` | 실제 기존 설정 백업과 적용안 | 해당 환경의 백업으로 유지; 일반 설정 예제로 복사하지 않음 |
| `operations/plan.json`, `events.jsonl` | 계획과 추가 방식의 로컬 실행 기록 | 그대로 유지; 새 repo나 사내 실행 승인으로 승격하지 않음 |

현재 runtime에 mount할 credential root는 `credentials/`이며 컨테이너 안에서는
`/run/secrets/query-man/databases/voc-db/{ca.crt,client.crt,client.key}`가 된다. Key는 root 소유,
group 10001, `0640`; credential directory는 `0750`이다. CA authority와 probes는 일반 app mount에
포함하지 않는다. 기존 `.env`는 삭제된 상태이고 이 작업에서 다시 만들지 않았다.

## Docker volume에 남아 있는 설정

`voc-db-data` volume이 컨테이너의 `/var/lib/postgresql`에 연결되어 있다. 당시 host mountpoint는
`/var/lib/docker/volumes/voc-db-data/_data`였다. 다른 Docker host에서 이 경로를 가정하지 않는다.

- 신규 공개 trust bundle: `/var/lib/postgresql/query-man-voc-db-client-ca-bundle.crt`
- 기존 서버 인증서·키는 재사용했다. 서버 인증서 SAN은 `voc-db`, `localhost`, `127.0.0.1`이다.
  Kubernetes에서 다른 DNS 이름으로 접속할 때 자동으로 그 이름까지 검증되는 것은 아니다.
- `PGDATA=/var/lib/postgresql/18/docker`의 `pg_hba.conf`, `pg_ident.conf`, `postgresql.auto.conf`에
  CA trust와 확인 계정의 인증 규칙을 적용했다. 기존 HBA/ident 규칙은 보존했다.
- PostgreSQL catalog에 확인 계정·CONNECT·database-local 기본값이 남아 있다.

따라서 호스트 작업 디렉터리를 삭제해도 DB의 데이터나 적용 설정은 되돌아가지 않는다.
반대로 `credentials/`를 삭제하면 다음 인증서 접속을 준비할 수 없고, `authority/`와 백업을 삭제하면
재발급·복구 수단을 잃는다. 개발 시작을 위한 정리 작업으로 삭제하지 않는다.

## 기존 코드를 그대로 배포하면 안 되는 이유

두 스크립트는 해당 작업을 재현하도록 container/image ID, network/IP, port, database/role/DN,
PGDATA/socket, 경로와 UID/GID를 고정했다. Query Passport에서는 승인된 환경 입력과 executor
binding으로 분리하고 잘못된 대상·지원하지 않는 topology를 거부해야 한다.

`apply-tls.py`는 당시 `.before`/`.proposed` 파일, plan의 hash와 기존 생성·rollback event에 의존한다.
특히 rollback은 설정 파일 전체를 과거 버전으로 복원한다. 그 이후 다른 운영 변경이 생겼다면
그대로 재사용할 수 없다. 새 도구는 이번 작업의 소유 변경, 전후 상태와 현재 drift를 확인해야 한다.

재사용해야 할 동작은 다음과 같다.

- 새 확인 계정은 안전한 HBA와 mapping이 실제 적용되기 전까지 `NOLOGIN`으로 둔다.
- 복구할 때도 확인 계정을 먼저 비활성화한 뒤 기존 local trust 규칙을 복원한다.
- stdout/stderr에 DB 원문 오류나 credential을 출력하지 않고 예상 오류를 분류한다.
- 읽기 전용 transaction에서의 쓰기 거부, timeout/cancel 후 rollback과 새 연결 복구를 검증한다.
- 인증서 만료와 미신뢰 CA는 단순한 접속 실패가 아니라 해당 실패 이유까지 구분한다.
- 기존 PUBLIC monitoring view 등 발견한 권한을 business grant와 혼동하지 않는다. 로컬 예외를
  다른 DB의 기본 allowlist로 전파하지 않는다.

## 안전한 개발 이관 순서

1. 현재 폴더와 비밀·백업은 보존한다. 새 repo에는 문서와 검토한 범용 코드만 작성한다.
2. M1을 외부 접속 없이 완료한다. 명령 실행은 CLI가 실제 만들어진 뒤 시작한다.
3. M2/M3는 승인된 별도 disposable PostgreSQL 환경에서 먼저 검증한다.
4. 필요한 경우 기존 voc-db의 정확한 상태와 범위를 다시 확인하고 bounded 회귀 검증을 수행한다.
5. Secret/PKI/운영 기록의 실제 관리 위치를 정한 뒤 그 소유자가 자료를 이관한다.
6. 새 실행 환경에서 접속·갱신·복구 가능성을 확인하고, 보존 의무와 승인이 확인된 자료만 정리한다.

이 문서에 적힌 기존 스크립트는 참고 대상이며 자동으로 실행할 명령이 아니다. Query Passport의
테스트 완료는 새 코드와 새 검증 결과로 증명한다.
