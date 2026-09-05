# 운영 설계

이 문서는 Query Passport의 운영 구현 목표다. 현재 M1 오프라인 CLI와 M2 로컬 Docker 읽기 전용 검증이 있으며 쓰기 기능과 Kubernetes 배포는 없고,
이 문서 작성은 기존 DB·PKI·Secret 변경의 실행 승인이 아니다. 명령과 결과 형식은
[Tool contract](tool-contract.md), 기존 작업의 위치와 한계는 [로컬 인계](local-handoff.md)를 따른다.

## 역할과 신뢰의 방향

Query Passport는 Query Man 스킬이 호출하는 인증서·DB 접속 준비 도구다. 발급기관 자체를
항상 운영하는 서비스는 아니다. 승인된 발급기관, Secret 저장소와 DB 실행 수단을 연결한다.
Query Man 앱은 실행 중 이 도구를 호출하지 않고, 전달받은 credential 파일로 DB에 접속한다.

| 담당 | 책임 | 맡기지 않는 것 |
|---|---|---|
| Query Man 스킬 | 요청 파악, 필요한 입력 수집, 계획 설명, 실행 범위 확인, 결과 해석 | 개인 키 열람, 프롬프트만으로 안전 보장 |
| Query Passport | 입력·대상 검증, 변경 계획, 승인 범위 내 실행, 접속 검증, 정제된 결과 | source 정책과 업무 데이터 권한 재정의 |
| PKI 담당 | 승인된 identity의 인증서 발급·갱신·폐기, CA 개인 키 보호 | CA 개인 키를 Query Man Pod에 전달 |
| DBA / DB executor | DB TLS·HBA·DN mapping 및 승인된 계정 설정 적용 | 요청 밖의 기존 grant·role·DB 변경 |
| 배포 / Secret 담당 | credential 전달, 파일 권한, 새 인스턴스 전환 | 인증서 발급만으로 앱 준비 완료 판단 |
| 환경 기록 담당 | 승인·적용·검증·복구 사실을 지정 저장소에 보존 | 실제 운영 기록을 Git 문서로 대체 |

현재 Query Man의 인증 단위는 **배포 하나 × database profile 하나**다. 같은 배포의 여러
Pod가 인증서를 공유하면 DB에는 같은 서비스 identity로 보인다. Source별 reader와 권한은
별도로 제한한다. 독립 폐기가 필요한 서비스까지 같은 개인 키를 공유하도록 확장하지 않는다.
이 단위를 변경하려면 기존 Query Man 계약과 영향 검토가 먼저다.
[현재 인증 계약](../../query-boy/docs/database-certificate-authentication.md)

| 확인하는 쪽 | 확인 자료 | 확인 대상 |
|---|---|---|
| Query Man Pod | 서버 CA와 중간 인증서, DB 서버 인증서의 이름 | 접속한 상대가 의도한 DB인가 |
| PostgreSQL | 클라이언트 발급 CA, client 인증서와 개인 키 소유 증명 | 허용한 서비스가 해당 DB 계정으로 접속하는가 |

서버 인증서를 발급한 CA와 클라이언트 인증서를 발급한 CA는 서로 달라도 된다. Pod의
`ca.crt`는 **DB 서버를 신뢰하기 위한 자료**이고, PostgreSQL의 client CA bundle은
**Query Man을 신뢰하기 위한 자료**다. 파일명에 CA가 들어간다는 이유로 서로 대체하지 않는다.
서버 이름까지 확인하는 `verify-full`을 유지한다.
[PostgreSQL 클라이언트 TLS](https://www.postgresql.org/docs/18/libpq-ssl.html)

파일 방식의 인증서가 생성된 로컬 PC·서버는 인증서의 사용 장소를 고정하지 않는다. 안전하게
전달된 일치하는 인증서·개인 키를 Pod에서 사용할 수 있다. DB는 Kubernetes 노드명이나 Pod명을
직접 인증하는 것이 아니다. Kubernetes ServiceAccount는 API/Secret 접근에 사용하는 별도 신원이고,
Query Man HTTP API 호출자의 신원도 DB 서비스 인증서와 구분한다.

## 산출물의 보관 경계

| 위치 | 보관할 산출물 |
|---|---|
| Query Passport Git | 도구 소스·테스트, 비밀 없는 입력/배포 템플릿, 운영 설명서 |
| Query Man Git | 기존 database profile, source package, 앱 코드와 기존 스킬 |
| 승인된 PKI 영역 | CA 개인 키, 발급·폐기 관리 정보, 발급 정책 |
| Secret 저장소 | 배포별 실제 client certificate/key, 서버 trust anchor와 chain |
| DB 서버 | 서버 certificate/key, client CA bundle, HBA·DN mapping·승인된 role 설정 |
| 환경별 기록·백업 저장소 | 승인 범위, 계획, 변경 전 상태, 적용 이력, 검증·복구 결과 |
| 격리된 테스트 영역 | 일시적으로 만든 미신뢰·만료·잘못된 DN 인증서와 테스트 DB |

개인 키·인증서 원문·비밀번호·토큰·인증정보 포함 DSN·실제 Secret manifest는 Git, image,
CLI argument, 환경변수, 채팅과 일반 log에 넣지 않는다. 자격 증명과 실행 수단을 지정하는 스킬의
공개 입력은 승인된 비밀 없는 service alias만 사용한다. 실제 provider reference와 credential 파일
경로는 실행 backend의 외부 설정에서 해석하며 agent의 입력·결과에 노출하지 않는다. 내부 경로를 안다는 사실도 접근
권한을 부여하지 않는다. 공개 계약은 [Tool contract](tool-contract.md)를 따른다.

Query Man Pod에 전달할 최종 레이아웃은 기존 계약을 유지한다.

```text
/run/secrets/query-man/databases/<database-profile-id>/
├── ca.crt       # 서버 검증용 CA와 필요한 intermediate
├── client.crt   # 클라이언트 인증서와 필요한 intermediate
└── client.key   # 해당 인증서와 일치하는 개인 키
```

개인 키는 실행 UID 소유 `0600`, 또는 root 소유·애플리케이션 전용 group의 `0640`으로 제한한다.
마운트는 읽기 전용이며, 부모 directory 접근과 symlink 최종 target의 소유자·권한도 확인한다.
같은 group에 속한 불필요한 컨테이너가 키를 읽을 수 있는 구성은 허용하지 않는다.
CA 개인 키·발급용 작업물·복구 백업·검증용 실패 인증서는 Query Man Pod에 전달하지 않는다.

## 실행 단계와 승인 범위

문서 작성과 내부 코드 개발은 실제 환경 변경 실행과 구분한다. 실행에서는 기존에 받은 명시적인
대상·범위 승인을 재사용하고, 범위가 늘어나거나 계획의 의미가 달라질 때만 추가로 확인한다.
승인된 환경의 access, scope, target, stop condition과 change-record 책임을 고정한다.

| 단계 | 수행할 일 | 다음 단계로 넘어갈 조건 |
|---|---|---|
| 조사 | 승인된 연결 수단으로 대상·버전·TLS·인증서 metadata·설정 소유권 확인 | 대상과 필요한 실행자 확정 |
| 계획 | 변경·보존 범위, 전제 상태, 단계별 검사, 중단·복구 방법 작성 | 검토 가능한 계획과 실행 승인 |
| 발급/수령 | 승인된 issuer 또는 제공된 credential reference 사용 | identity·유효기간·chain·key 일치 검증 |
| DB 적용 | 승인된 trust·HBA·DN mapping·role 변경만 실행 | 설정 parse/reload 및 실제 상태 검증 |
| 배포 전달 | 지정된 Secret/credential 경계에 버전별 전달 | 실제 실행 UID·경로·권한 검증 |
| 접속 검증 | 실제 클라이언트로 성공·거부·timeout·복구 확인 | 실패 없이 DB 준비 판정 가능 |
| 전환/정리 | 승인된 배포 전환과 이전 credential 처리 | 새 연결 검증, 폐기 정책과 기록 완료 |

발급 승인이 DB 설정 변경이나 Kubernetes 배포 승인을 대신하지 않는다. Source 등록 승인이
없는 DB 준비 작업으로 source reader, 업무 view, base table, 신규 DB를 만들지 않는다.
DB 접속 확인용 계정이 필요하면 목적·수명·권한·삭제 책임을 계획에 명시하고 별도 범위로 포함한다.

## 대상 고정과 부분 실패 처리

계획은 이름만 같은 다른 컨테이너나 DB에 재사용할 수 없어야 한다. 환경 alias, 실제 DB 대상,
실행자 권한, 소유한 설정 구간, 허용된 변경과 관측한 revision/hash를 연결한다. Apply 직전에
이 값들을 다시 확인하고, 계획 이후 변경이 있으면 적용을 멈추고 새 계획을 만든다.
동일 대상 변경은 한 실행자가 담당하며, 충돌하는 실행을 막는 lock의 저장 위치·수명·복구를 정의한다.

- 기존 서버 certificate/key, client CA, 다른 서비스의 HBA·mapping·grant는 소유 범위 밖이면 보존한다.
- HBA 순서와 실패 시 뒤쪽 규칙에 미치는 영향을 검사한다. 평문·password·넓은 CIDR/grant로 우회하지 않는다.
- 새로 만드는 로그인 계정은 우선 `NOLOGIN`으로 둔다. 거부 규칙·mapping과 trust가 실제로 로드되고
  검증된 뒤에만 승인된 계정을 `LOGIN`으로 전환한다. 기존 계정의 상태를 임의로 바꾸지 않는다.
- DB 준비용 최소 계정에는 업무 데이터 권한을 주지 않는다. 기존 `PUBLIC`·membership·routine
  권한도 검토하여 실효 권한이 계획과 다르면 중단한다. 공유 권한을 일괄 revoke하지 않는다.
- `default_transaction_read_only` 등 role 기본값은 방어 수단이지만 사용자가 바꿀 수 있는 설정이다.
  이를 불변 권한 경계로 설명하지 않는다. 실제 최소 권한과 Query Man의 read-only transaction,
  source/SQL allowlist는 별도의 기존 통제를 유지한다.

단계별로 시작 전 상태와 완료한 변경을 남긴다. 프로세스 종료, timeout, reload 실패, Secret 전달
실패 후에는 상태를 재조사해 `미적용/일부 적용/검증 완료/복구 필요`를 구분한다. 재실행이 같은
role·certificate를 무조건 중복 생성하거나 계획 밖 변경을 덮어쓰지 않게 한다.

복구는 해당 실행이 소유한 변경을 대상으로 한다. 작업 도중 다른 DBA가 수정한 전체 HBA·설정을
옛 백업으로 무조건 덮어쓰지 않는다. 전제 상태가 맞는 경우에만 소유 구간을 복원하고, drift가 있으면
안전한 중단 상태와 복구 지침을 반환한다. 새 계정의 규칙을 제거할 때는 **해당 계정을 먼저
`NOLOGIN`으로 막아** 남아 있는 legacy trust/password 규칙으로 열리지 않게 한다.
기존 세션은 `NOLOGIN`만으로 종료되지 않으므로 종료가 필요한 상황은 승인 범위에 명시한다.

## DB 준비 완료와 검증 결과

검증은 관리자 socket 접속만으로 끝내지 않는다. 실제 runtime UID와 credential mount로 의도한
DB·계정·TLS·server hostname·client identity를 확인한다. 실행 도구는 DB 원문 오류 대신 비밀 없는
분류와 재시도 가능 여부를 반환한다. 도구 종료 코드와 증거 저장 성공도 완료 판정에 포함한다.

| 검증 범주 | 구현할 주요 확인 |
|---|---|
| 정상 접속 | 올바른 인증서, 실제 endpoint·DB·계정, TLS와 읽기 전용 transaction |
| 서버 검증 거부 | 신뢰하지 않는 서버 CA, 잘못된 hostname |
| 클라이언트 인증 거부 | 인증서 없음·만료·미신뢰 CA·미매핑 DN·key 불일치 |
| 인증 범위 거부 | 허용하지 않은 DB/계정, 평문 연결 |
| 실행 수명 | timeout·client cancel 후 rollback, 같은 연결/후속 연결의 복구 |
| 파일·자원 | 개인 키 접근 제한, read-only mount, 승인된 연결 수 제한 |

거부 검증은 승인된 대상·횟수·동시성 안에서 수행하고 업무 데이터나 실제 Secret을 결과로 내보내지
않는다. PKI 폐기 검증, source 외 객체 거부, metadata admission, `/ready`와 bounded query는 각
준비 단계와 실행 범위에 맞춰 별도 판단한다. Source가 없는 DB 접속 성공을 **Query Man 앱이나
업무 조회의 준비 완료로 표시하지 않는다**. 전체 활성화 기준은 Query Man이 소유한다.
[Query Man 운영 기준](../../query-boy/docs/operations.md)

## 인증서 갱신·폐기

갱신은 새 credential을 버전별로 준비하고 필요한 새 trust·mapping을 먼저 추가하는 절차로 설계한다.
CA가 바뀌면 승인된 기간 동안 이전/신규 trust를 겹쳐 두고 새 인스턴스에서 성공·거부 조건을 검증한다.
검증 후 배포를 전환하고 이전 credential의 사용 종료를 확인한다. 기존 pool의 TLS 세션이 남으므로
파일 교체만으로 완료하지 않고 새 프로세스/Pod에서 신규 연결을 확인한다.

같은 CA로 인증서를 다시 발급해도 이전 인증서가 자동 폐기되지는 않는다. 이전 CA 전체를 제거하면
같은 CA를 쓰는 다른 클라이언트도 영향을 받는다. CRL 등의 지원 여부·설정·reload·기존 세션 처리,
폐기 반영 검증은 환경별 계획에 명시한다. 미구현 단계에서는 폐기 지원을 주장하지 않는다.
[PostgreSQL 서버 TLS와 CRL](https://www.postgresql.org/docs/18/ssl-tcp.html)

새 배포의 일반 실패에서는 승인된 직전 credential/배포로 복구할 수 있다. 개인 키 유출이 의심되면
이전 키로 되돌리지 않고 incident 대응, 신뢰/인증 차단과 재발급을 우선한다.
만료 예정 알림, 발급 담당자, 갱신 여유 기간과 폐기 책임은 운영 인계 산출물에 포함한다.

## 로컬 PKI와 Kubernetes 적용 방향

Disposable 로컬 테스트에서는 격리된 CA 생성과 실패 인증서 생성 기능을 구현할 수 있다. 실제 운영은
사내 승인 issuer와 Secret 전달 수단을 먼저 확인한다. 로컬 CA를 신뢰하도록 production을 자동 변경하거나
CA 개인 키를 Query Passport Git 또는 Query Man Pod로 옮기지 않는다.

Kubernetes는 아직 조사하거나 구성하지 않았다. 다음 항목은 구현 전 결정할 사항이다.

- 기존 Kubernetes Secret 또는 사내 Secret store/CSI 등 제공 수단을 선택한다. Secret 참조만 있는
  템플릿과 실제 Secret 내용을 구분하고, key를 담은 manifest나 base64 값을 Git에 저장하지 않는다.
- Secret 읽기뿐 아니라 Pod 생성·수정으로 Secret을 마운트할 수 있는 권한까지 RBAC 범위를 검토한다.
  저장 시 암호화와 필요한 컨테이너에만 mount하는 설정을 확인한다.
- 실제 volume에서 UID/group·mode·symlink와 읽기 전용 조건을 검사한다. 특정 provider가 소유권을
  원하는 대로 제공한다고 가정하지 않는다. 지원되지 않는 구성은 키 권한을 넓히지 않고 중단한다.
- Secret/CSI 갱신 전파 방식과 배포 전환을 확인한다. 파일 자동 갱신을 기존 연결의 재인증으로 간주하지 않는다.
- 같은 배포의 replica가 인증서를 공유하더라도 연결 예산은 별개다. `Pod 수 × worker/pool 설정`과
  DB role의 전체 연결 한도를 함께 계산하고, rollout 중 겹치는 Pod까지 검토한다.
- DB endpoint 이름과 서버 인증서 SAN, 실제 Pod egress/NAT 주소와 HBA·방화벽을 각각 확인한다.
  노드가 바뀌어도 서비스 identity는 유지할 수 있지만 Secret 전달·네트워크 조건은 다시 충족해야 한다.

노드가 인증 주체는 아니어도 해당 노드의 권한이 credential 노출에 영향을 줄 수 있다. 노드와 workload
격리도 배포 설계에 포함한다. 제공자별 API나 cluster 권한은 조사 후 필요한 범위로 추가한다.
[Kubernetes Secret 보안](https://kubernetes.io/docs/concepts/security/secrets-good-practices/),
[Secret 동작과 보안 경계](https://kubernetes.io/docs/concepts/configuration/secret/)

## 이후 검토할 연결 구조와 기록

MVP는 승인된 직접 PostgreSQL 연결을 우선한다. 회사 환경의 PgBouncer·DB replica 구성은 현재
구현·검증된 지원 범위가 아니다. 지원 밖 구성을 직접 연결로 임의 해석하거나 TLS 정책을 낮추지 않는다.
PgBouncer는 client→pooler와 pooler→DB 각 구간의 TLS·신원·mapping·pool mode·취소 의미를
조사해야 한다. Replica는 역할 판별, endpoint routing, 인증서 이름, DB별 권한·설정 반영과 장애 전환
동작을 확인해야 한다. Query Man의 현재 계약 변경이 필요하면 별도 영향 검토가 먼저다.

Protected 환경의 승인·적용·실패·복구·검증 사실은 승인된 append-only/immutable 기록 시스템에 남긴다.
로컬 JSONL은 개발용 실행 이력이며 immutable evidence가 아니다. 두 기록의 보증 수준을 구분한다.
공통 transition artifact와 governance 기록은 single-writer로 관리한다. 기록에는 credential 원문 대신
정책이 허용하는 reference·fingerprint·유효기간·정제된 판정만 남기고 실제 백업은 접근 제한된 위치에 둔다.
