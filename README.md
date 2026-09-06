# Query Passport

Query Man 스킬이 호출하는 PostgreSQL 인증서 준비 CLI다. Python 3.12+와 uv를 사용하며
입력과 출력은 JSON이다. Query Man 앱의 조회 경로에는 런타임 의존성을 추가하지 않는다.

## 현재 기능: 0.4.0 MVP

| 기능 | 명령 |
|---|---|
| 지원 기능 확인·오프라인 입력 검사·계획 | `capabilities`, `inspect`, `plan` |
| 실제 TLS·인증서·DB 연결 검사 | `verify` |
| 로컬 인증서 준비 | `prepare` → `issue` → `apply` → `deliver` |
| 같은 CA로 인증서 갱신 | `prepare` (`intent: rotate`) → `rotate` |
| 마지막 작업 기록 확인 | `status` |

실패하면 비밀 없는 오류 코드와 비영 종료 코드를 반환한다. 자동 재시도·보상 변경·롤백은 없다.
원인을 해결한 뒤 같은 명령과 operation 참조로 다시 실행한다. 불완전한 파일이나 변경된 대상은
덮어쓰지 않고 오류로 거절한다. 모든 부분 실패를 재실행만으로 해결한다고 보장하지 않는다.

`inspect`·`plan`은 DB·Docker·PKI에 접근하지 않는다. `plan`은 항상 `executable: false`다.
Source 0개는 정상이며 DB 연결 성공도 source/reader/application readiness 성공을 뜻하지 않는다.
로컬 PostgreSQL 18/UTF8·Docker를 지원한다. 로컬 voc-db 전환과 Query Man 스킬 연계 검증은 완료했다.
앱·Pod 인증서 mount/새 연결 검증, Kubernetes 전달, 운영 PKI·폐기는 미완료다.

가끔 사용할 때는 [설치·설정·발급·갱신·오류 대응 안내](docs/quickstart.md)를 먼저 읽는다.

## 설치와 실행

```bash
uv sync --locked
uv run --locked query-passport capabilities
uv run --locked query-passport inspect --request examples/request.json
uv run --locked query-passport plan --request - < examples/request.json
uv tool install .
```

입력 파일은 `--workspace DIR`(기본 현재 디렉터리) 안의 상대 경로로 지정한다.
Live 명령은 별도 operator binding이 필요하다. 예시 파일은 실제 대상 등록이나 변경 승인이 아니다.

```bash
uv run --locked pytest -q
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy
uv build
```

## 문서와 호환성

- [개발 계획](docs/development-plan.md): 범위와 검증 결과
- [호출 계약](docs/tool-contract.md): JSON·오류·capability
- [로컬 executor](docs/local-executor.md): 실제 연결 검사 설정
- [로컬 lifecycle](docs/local-lifecycle.md): operator 설정과 발급·갱신 예시
- [운영 경계](docs/operations.md): 대상·비밀정보·실패 시 동작
- [기존 작업 인계](docs/local-handoff.md): 과거 작업 참고 자료

0.4.0은 0.3.0의 복구 계약을 제거한 변경이다. Live capability는 v2이고 `rollback`은 지원하지 않는다.
Query Man consumer의 0.4.0 대응과 스킬→실제 DB 검증을 완료했다. 사용 시 대응 commit이 포함된
Query Man checkout을 사용한다. 기존 작업 기록이나 credential store를
자동 변환하지 않는다. 이전 전달 store는 소유 형식 오류로 거절하며 새 전용 경로를 사용한다.
