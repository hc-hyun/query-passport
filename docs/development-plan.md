# 개발 계획

Status: 0.4.0 MVP·Query Man consumer 대응·로컬 voc-db 전환 완료 / 앱·Pod 연결 검증은 실제 사용 시 진행

## 현재 범위

| 단계 | 구현한 기능 |
|---|---|
| M1 | Python/uv CLI, capabilities·inspect·plan, JSON 검증·비밀 비노출·source 0개 |
| M2 | 로컬 Docker에서 TLS·인증서·대상·읽기 전용 접속 검사 |
| M3 MVP | prepare·issue·apply·deliver, 같은 CA의 rotate, 마지막 기록 status |

0.3.0의 rollback 명령, DB·credential 복원, 실패 시 보상 DB 변경, unknown/partial_failure
상태 처리와 오류 재분류를 제거했다. 접속할 때 고의 timeout·cancel을 발생시키고 복구하던 진단도 제거했다.
실제 연결 검사, 입력·대상·파일 권한 검사, 실행 timeout과 임시 실행 자원 정리는 유지한다.

## 코드 책임

| 구분 | 코드 |
|---|---|
| 입력·JSON 경계 | `cli.py`, `contract.py`, `lifecycle_contract.py` |
| 기본 인증서 흐름 | `local_lifecycle.py`, `local_pki.py`, `credential_delivery.py` |
| DB 인증 설정·접속 검사 | `db_admin.py`, `db_config.py`, `executor.py`, `verify_worker.py`, `policy_verification.py`, `policy_worker.py` |
| 재실행 동일성·동시 변경 방지 | `operation_store.py`, `lifecycle_binding.py` |
| 제한된 프로세스 실행 | `process.py` |
| 테스트 | root `tests/`; 실제 DB fixture는 opt-in |

실패 전용 복구 엔진은 없다. 오류는 JSON 경계에서 정규화하며 알려진 코드의 의미를 보존한다.
부분 파일의 자동 수선은 MVP 밖이다. 재실행은 같은 작업 ID로 하며 대상·파일 충돌은 오류다.

## 검증

Linux/POSIX, Python 3.12+, uv가 기본 환경이다. 실제 연결 검사는 로컬 Docker와
미리 준비된 PostgreSQL 18 및 Query Man runtime image가 필요하다.

```bash
uv sync --locked
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy
uv run --locked pytest -q
uv build
QUERY_PASSPORT_DOCKER_TESTS=1 uv run --locked pytest -q --tb=short
```

2026-09-05 검증 결과:

- 기본 전체 테스트: **1,066 passed, 41 skipped** (45.77초). Skip은 opt-in 실제 DB 검사다.
- 실제 DB 전체 실행에서 삭제한 `reconnect` 필드 참조가 드러나 수정했다.
  영향받은 관리자 identity·설치 wheel·M2 연결·M3 흐름 4개 파일을 재실행해 **32 passed** (208.47초)를 확인했다.
- 나머지 실제 DB 9개(새 M3 fixture 1개, monitoring 8개)는 앞선 전체 실행에서 통과했다.
  전체 실행 1회가 모두 통과한 결과로 합산해서 보고하지 않는다.
- 원래 오류 보존·임시 실행 자원 정리 관련 검사: **157 passed**.
- Ruff lint/format, mypy(17개 source 파일), wheel/sdist 빌드 통과.
- 실제 CLI capabilities와 source 0개 offline plan 확인: rollback 미지원, executable false,
  DB·인증서·인증·application readiness not_checked.
- 문서의 로컬 링크·내부 anchor와 JSON 예시 일치 확인.

이번 단순화에서 기존 DB·호스트 credential·Query Man 저장소는 변경하지 않았다.
이 시점에는 삭제한 0.3.0 consumer E2E를 대체할 0.4.0 연계 검증이 남아 있었다. 이후 결과는 아래에 기록한다.

## 2026-09-06 E2E 검증

설치 CLI→새 disposable PostgreSQL의 E2E·통합 테스트를 한 번의 실행에서
**41 passed, 0 failed, 0 error, 0 skipped**로 확인했다(277.36초).
발급·적용·전달·접속·갱신, 인증 거부, drift와 오류 후 재실행을 포함한다.
Query Man consumer 연계는 이번 검증에 포함하지 않았다.

첫 시도는 기록 실행기의 umask 상속과 fixture hook 판별 오류로 실패했다.
제품 코드 변경 없이 기록 실행기만 수정한 뒤 위 전체 테스트를 재실행했다.
실패 시도와 최종 결과를 모두 보존했다.

Git bundle, 미커밋 코드 스냅샷, 실제 테스트 wheel, JSON 실행 이력·JUnit·로그·체크섬과
복원 안내를 저장소 밖의 전용 폴더에 보존했다. Git clone 및 코드 스냅샷 추출 복원을 검증했고,
wheel의 Python source 17개가 스냅샷과 일치함을 확인했다. 기존 DB·호스트 인증서는 변경하지 않았다.

## 2026-09-06 Query Man 연계와 실제 DB 전환

환경에 보존된 `voc-db-v04-20260906` 점검 기록과 운영 인계를 확인했다.
Query Man 호출부는 0.4.0·v2 live capability·7개 검사·새 오류 계약에 대응하고 rollback 호출을 제거했다.
스킬→설치 CLI→실제 voc-db의 발급·DB 적용·전달·갱신·재검증을 완료했다.
공통 호출부 변경 7개 파일은 Query Man `homework`의 `105520b`에 커밋했다.
이전 확인 계정은 운영자가 NOLOGIN으로 전환했고 기존 파일은 별도 보관했다.
이는 Passport가 rollback·기존 계정 퇴역·PKI 폐기를 구현했다는 뜻이 아니다.

기록된 검증은 Query Man 764 passed / DB lane 11 deselected, Passport 기본 1,066 passed,
별도 Docker 통합 41 passed, 실제 DB 연결 검사 7개 모두 passed다.
Source는 0개이며 앱·Pod mount, 앱 새 연결, source/reader·application readiness는 미검증이다.
실제 경로·작업 ID·만료일·인증서와 전환 자료는 환경 기록에 보존하며 이 저장소로 복사하지 않는다.

커밋 전 Query Man Ruff·mypy를 다시 확인했고 전체 테스트 **764 passed / 11 deselected**를 확인했다.
실제 0.4.0 CLI의 capabilities를 공통 helper로 읽는 smoke도 통과했다.
Passport 변경은 문서와 비활성 합성 binding 예시뿐이다. 예시의 오프라인 검증·문서 링크/anchor·JSON
예시 일치를 확인했으며, 이 문서 마무리 작업에서 실제 DB 변경이나 E2E 재실행은 하지 않았다.

## 2026-09-06 테스트 정리

가끔 사용하는 MVP에 맞춰 공통 검증·오류 전달의 중복 조합을 줄였다. 제품 코드와 실제 DB
통합 테스트 41개는 변경하지 않았다. 수집 항목은 **1,107개 → 942개**로 165개 줄었다.

| 대상 | 이전 → 이후 | 정리 기준 |
|---|---|---|
| CLI | 88 → 47 | 알 수 없는 필드는 각 중첩 위치의 대표 입력으로 비노출을 검사; 공통 인자 오류 중복 제거 |
| Lifecycle 계약 | 135 → 74 | prepare/operation 두 입력 형태를 대표로 검사; 공통 JSON 파서 재검사 제거 |
| DB 설정 | 118 → 91 | 같은 식별자 검증기의 필드×문법 조합 제거; 각 문법과 필드는 유지 |
| Executor | 71 → 47 | 실행·정리 오류의 전체 곱 대신 예외 종류와 정리 결과별 대표 조합 유지 |
| Policy 검사 | 86 → 74 | 공통 cleanup의 반복 조합을 줄이고 호출부의 원래 오류 보존 확인 |

테스트 유지 기준:

- **주요 기능:** 발급·적용·전달·갱신, 명령별 dispatch, source 0개와 오프라인 not_checked를 유지한다.
- **입력·보안:** 입력 규칙은 해당 검증기에서 검사하고 CLI는 JSON·종료 코드·비노출을 확인한다.
  대상 drift, 권한, 인증서 거부, 기존 파일 보존은 서로 다른 실패 조건이므로 유지한다.
- **오류 처리:** 정확한 오류 전달과 부분 상태 보존을 확인한다. 공통 함수의 모든 입력 조합을
  호출 계층마다 반복하거나 제거한 복구 기능의 테스트를 다시 추가하지 않는다.

정리 후 `uv run --locked pytest -q`: **901 passed, 41 skipped** (39.50초).
Ruff lint/format, mypy(17개 source 파일), `git diff --check`를 통과했다.
Skip은 opt-in DB 검사이며 이번 작업에서는 Docker·실제 DB E2E를 재실행하지 않았다.
정리 전 테스트는 Git `f4d1c4f`에 보존되어 있다.

## 바로 이어서 할 첫 작업

필수 기능 추가는 없다. [짧은 사용 안내](quickstart.md)로 설치·operator 설정·발급·갱신·오류·만료를 확인한다.
실제로 앱에서 사용할 때 새 세대 mount와 앱 새 연결, 필요한 source/reader·readiness를 검증한다.
CI·자동 갱신·알림·추가 복구 기능은 현재 필수 범위에 넣지 않는다.
Kubernetes·운영 PKI·폐기는 실제 환경 요구가 생길 때 별도 범위로 진행한다.
