# auth-service

계정과 인증을 담당하는 마이크로서비스. **JWT를 발급하는 유일한 주체다.**

> 상태: **스캐폴딩 전** — 작업 항목 AU-01부터 시작한다.

| 항목 | 값 |
| --- | --- |
| 포트 | 8083 |
| 데이터베이스 | `sp_auth` (MySQL 8.0) |
| 소유 테이블 | `account`, `refresh_token` |
| 기본 패키지 | `com.example.auth` |
| JWT 역할 | **발급(서명)** — RS256 RSA **개인키** 보유 |
| 작업 항목 접두어 | `AU-xx` |

## 문서

정본 문서는 별도 저장소에 있다.

```bash
git clone https://github.com/yuno110/sp-docs.git ../sp-docs
```

| 무엇을 찾는가 | 문서 |
| --- | --- |
| 무슨 문서를 읽어야 하나 | `sp-docs/README.md` |
| 지금 할 일 | [`docs/checklist.md`](docs/checklist.md) |
| 작업 항목의 상세 | `sp-docs/plan/phase1.md` §4 |
| 구현·테스트 절차 | `sp-docs/process/dev-workflow.md` |
| 엔드포인트·에러 코드·JWT Claim | `sp-docs/api-contract.md` |
| 엔티티·컬럼 | `sp-docs/domain-model.md` §2 |
| 기능 요구사항 | `sp-docs/requirements/member.md` (담당 열이 `auth`인 것) |
| **왜 서비스가 셋인가** | `sp-docs/adr/0012-auth-as-separate-service.md` |

AI 워커는 [`CLAUDE.md`](CLAUDE.md)를 먼저 읽는다.

## 책임 범위

**계정은 auth가, 프로필(닉네임)은 member가 소유한다.**

| 패키지 | 관심사 | API 경로 |
| --- | --- | --- |
| `auth` | 세션·토큰 행위 — 로그인, 재발급, 로그아웃 | `/api/v1/auth/**` |
| `account` | 계정 리소스 — 생성, 이메일 중복 확인, 조회, 비밀번호, 탈퇴 | `/api/v1/accounts/**` |

두 패키지 사이에 단방향 제약을 두지 않는다. 비밀번호 변경·계정 탈퇴가 `account` 갱신과 `RefreshToken` 삭제를 **한 로컬 트랜잭션**으로 묶어야 하기 때문이다.

## 가입과 탈퇴가 2단계인 이유

계정과 프로필이 다른 서비스에 있으므로 분산 트랜잭션을 피한다. 클라이언트가 순서대로 호출한다.

```
[가입]  1. POST   :8083/api/v1/accounts     계정 생성
        2. POST   :8083/api/v1/auth/login   로그인
        3. POST   :8081/api/v1/members      프로필 등록 (member)

[탈퇴]  1. DELETE :8083/api/v1/accounts/me  계정 탈퇴 (비밀번호 재확인)
        2. DELETE :8081/api/v1/members/me   프로필 탈퇴 (member)
```

**"계정만 있고 프로필이 없는 상태"는 정상이다.** 그 상태에서 로그인·재발급·로그아웃·계정 탈퇴가 모두 된다. 글·댓글 작성만 막힌다.

**탈퇴는 계정이 먼저다.** member는 비밀번호를 갖지 않으므로 프로필을 먼저 지우면 재확인이 구조적으로 불가능해진다. 중간 실패 시에도 계정 먼저 쪽이 아무것도 비가역으로 파괴하지 않는다. 전체 비교는 `sp-docs/adr/0012` §5에 있다.

## 주요 제약

- **`sp_member`·`sp_board`를 조회하지 않는다.** 같은 MySQL 인스턴스에 있어도 크로스 스키마 조인 금지
- **다른 서비스를 호출하지 않는다.** auth는 member·board를 모른다. 호출은 항상 auth 쪽으로 들어온다
- **닉네임을 다루지 않는다.** 닉네임은 member 소유다. 계정에는 이메일·비밀번호·권한만 있다
- **JWT Claim에 `nickname`을 넣지 않는다.** 소유하지 않은 값을 서명하지 않는다
- **로그인·재발급은 `account.deleted = false`를 검사한다.** 검사하지 않으면 탈퇴 계정이 토큰을 계속 갱신한다
- JWT 처리는 Spring Security 표준(`NimbusJwtEncoder`)을 쓴다. 서명 로직을 직접 만들지 않는다
- 시간대는 실행 환경이 정한다. 코드나 `build.gradle`에서 설정하지 않는다 (`sp-docs/adr/0011`)

## 실행 (스캐폴딩 이후)

**1차는 Docker를 사용하지 않는다.** MySQL은 로컬에 직접 설치한다.

```sql
CREATE DATABASE sp_auth DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
```

```bash
./gradlew bootRun --args='--spring.profiles.active=local'
```

| 환경변수 | 필수 | 설명 |
| --- | --- | --- |
| `JWT_PRIVATE_KEY_LOCATION` | O | 개인키 **경로** (`file:`·`classpath:`). **기본값 없음** — 없으면 기동 실패 |
| `CORS_ALLOWED_ORIGINS` | O | 허용 오리진 목록. **기본값 없음.** 비었거나 `*`가 섞이면 기동 실패 |
| `DB_URL` | | 기본값 `jdbc:mysql://localhost:3306/sp_auth` |
| `DB_USERNAME` / `DB_PASSWORD` | O (비밀번호) | |

로컬에서는 환경변수 대신 `src/main/resources/application-local.yml`에 넣는다 (`.gitignore` 대상). 절차는 `sp-docs/tech-stack.md` §4.3.1에 있다.

- API 문서: http://localhost:8083/swagger-ui.html
- 헬스체크: http://localhost:8083/actuator/health

## 키 배치

RSA 키 페어 생성은 `sp-docs/tech-stack.md` §4.2에 있다.

| 키 | 어디에 | 커밋 |
| --- | --- | --- |
| `private.pem` | **저장소 밖.** 현재 `~/keys/sp/private.pem`. `application-local.yml`로 경로를 준다 | **절대 금지** |
| `public.pem` | `sp-member`·`sp-board`의 `src/main/resources/jwt-public.pem` | 가능 |

**공개키 배포 지점이 두 곳이다.** 두 사본이 같은 키인지는 통합 검증 I-01에서 확인한다.
