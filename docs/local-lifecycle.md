# 로컬 lifecycle 구현과 검증

M3는 아직 구현 중이다. 이 문서는 내부 backend와 검증 경계를 설명한다.
현재 공개 CLI 명령은 `capabilities`, `inspect`, `plan`, `verify`이며, 아래 내부 API를
공개 쓰기 명령이나 완료된 운영 절차로 취급하지 않는다. Rotation과 실제 voc-db 전환도 남아 있다.

## 구현 경로

`local_lifecycle.prepare()`는 승인된 로컬 binding으로 대상과 설정을 조사하고, 기존 role과
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

## 기록·실패·복구

실행 기록은 OS 계정의 `~/.local/state/query-passport/operations/`에 보관한다. Operation과
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
QUERY_PASSPORT_DOCKER_TESTS=1 uv run --locked pytest -q tests/test_m3_fixture.py tests/test_m3_integration.py --tb=short
```

Opt-in 검사는 새 내부 network·PostgreSQL·외부 `/var/tmp` PKI만 만들고 소유 label과 directory
identity를 확인해 자신이 만든 fixture만 정리한다. 기존 voc-db·호스트 자격 증명·백업을 검사
대상으로 선택하지 않는다. 실제 운영 자료를 이 fixture로 복사하지 않는다.

검증 결과와 미완료 사항은 [개발 계획](development-plan.md#m3-진행-기록)에 기록한다.
