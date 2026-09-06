# 개발 계획

Status: 0.4.0 MVP 단순화 / 기존 DB 전환과 Query Man consumer 갱신 미완료

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
삭제한 0.3.0 consumer E2E는 0.4.0 호환성 검증을 대신하지 않으며 consumer 갱신은 아래 후속 작업이다.

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

## 바로 이어서 할 첫 작업

1. Query Man consumer를 0.4.0의 v2 live capability와 오류 계약에 맞춘다. 현재 외부 저장소는 변경하지 않는다.
2. 기존 DB 전환 필요 시 새 경로·대상을 고정하고 별도 검증한다. 현재 전환은 중단 상태다.

Kubernetes, 운영 PKI, 폐기, 자동 갱신 스케줄러와 장애 복구 자동화는 MVP 범위에서 제외한다.
기존 voc-db·호스트 credential·백업·기록을 이 작업에서 변경하거나 이관하지 않는다.
