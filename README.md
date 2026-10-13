# auth-service

계정과 인증을 담당하는 마이크로서비스. **JWT를 발급하는 유일한 주체다.**

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

## 로컬 실행

**1차는 Docker를 사용하지 않는다.** MySQL은 로컬에 직접 설치하고 `gradlew bootRun`으로 띄운다 (`sp-docs/tech-stack.md` §4).

### 1. MySQL — 최초 1회

```sql
CREATE DATABASE sp_auth DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
SET PERSIST time_zone = '+09:00';
```

시간대를 `SET PERSIST`로 두는 이유와 확인 쿼리는 `sp-docs/tech-stack.md` §4.1에 있다. 스키마는 Flyway가 만든다 — `src/main/resources/db/migration`이 유일한 출처이므로 테이블을 손으로 만들지 않는다.

### 2. RSA 키 페어 — 최초 1회

아래 "개인키 배치"를 먼저 끝낸다. **키가 없으면 기동이 실패한다.**

### 3. ADMIN seed 해시 — 최초 1회

`V3`가 ADMIN 계정을 넣을 때 쓸 BCrypt 해시를 만든다. 해시는 Flyway placeholder로 주입하며 저장소에 두지 않는다 (`sp-docs/requirements/member.md` §10.2).

```bash
./gradlew bcrypt -Ppassword=<로컬에서_쓸_관리자_비밀번호>
```

출력된 한 줄을 `application-local.yml`의 `adminPasswordHash`에 넣는다. **운영 해시는 이 값과 달라야 한다.**

### 4. `application-local.yml` — 최초 1회

로컬에서는 환경변수 대신 파일로 준다. 이 파일은 `.gitignore`에 있어 **평문으로 적어도 커밋되지 않는다** (`sp-docs/tech-stack.md` §4.3.1).

```bash
cp src/main/resources/application-local.yml.example src/main/resources/application-local.yml
# 파일을 열어 MySQL 비밀번호 · adminPasswordHash · 개인키 경로를 채운다
```

### 5. 실행

```bash
./gradlew bootRun --args='--spring.profiles.active=local'
./gradlew test    # 프로파일은 build.gradle 이 test 로 고정한다. 로컬 설정·실제 키를 쓰지 않는다
```

- API 문서: http://localhost:8083/swagger-ui.html (**`prod` 프로파일에서는 404다**)
- 헬스체크: http://localhost:8083/actuator/health — `/actuator`에서 노출되는 것은 이것뿐이다

### 환경변수

`local` 프로파일은 아래를 `application-local.yml`에서 읽는다. 배포 환경에서는 그 파일을 두지 않고 환경변수로 주입한다 (`sp-docs/tech-stack.md` §4.3).

| 환경변수 | 기본값 | 설명 |
| --- | --- | --- |
| `DB_PASSWORD` | **없음** | MySQL 비밀번호. 없으면 `Access denied ... (using password: YES)`로 기동 실패 — 비밀번호가 틀린 것이 아니라 값이 없는 것이다 |
| `JWT_PRIVATE_KEY_LOCATION` | **없음** | 개인키 **경로** (`file:`·`classpath:`). PEM 본문이 아니다 |
| `ADMIN_PASSWORD_HASH` | **없음** | ADMIN seed의 BCrypt 해시. 없으면 마이그레이션 전에 기동이 실패한다 |
| `CORS_ALLOWED_ORIGINS` | **없음** | 허용 오리진 목록(쉼표 구분). 비었거나 `*`가 섞이면 기동 실패 |
| `DB_URL` | `jdbc:mysql://localhost:3306/sp_auth?serverTimezone=Asia/Seoul&characterEncoding=UTF-8` | |
| `DB_USERNAME` | `root` | |

**비밀값과 정책값에는 기본값을 두지 않는다.** 임의 기본값을 두면 그 값이 정해진 정책인지 임시값인지 구분할 수 없고 운영에 그대로 나간다. 없으면 기동이 실패하는 것이 의도된 동작이다.

시간대는 실행 환경이 정한다. 환경변수로 넘길 것은 없고, JVM이 KST가 아니어도 DB 경계는 고정된다 (`sp-docs/tech-stack.md` §6.2).

## 개인키 배치

**이 저장소에 개인키를 두지 않는다.** `.gitignore`에 넣더라도 실수 한 번이면 이력에 남는다. 키 관리 규칙은 `sp-docs/security.md` §3이 정본이다.

1. 키 페어를 만든다 (`sp-docs/tech-stack.md` §4.2). 생성 디렉터리는 저장소 밖이어야 한다

   ```bash
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
   openssl rsa -in private.pem -pubout -out public.pem
   ```

2. 개인키를 저장소 밖에 둔다. 현재 쓰는 위치는 `~/keys/sp/private.pem`이다

   ```bash
   mkdir -p ~/keys/sp && mv private.pem ~/keys/sp/
   ```

3. 경로를 `application-local.yml`에 적는다. **키 본문이 아니라 경로다**

   ```yaml
   jwt:
     private-key-location: file:${user.home}/keys/sp/private.pem
   ```

4. 공개키를 `sp-member`·`sp-board`의 `src/main/resources/jwt-public.pem`에 복사한다. 공개키는 커밋해도 된다 — 유출돼도 토큰을 위조할 수 없다

5. 기동해서 확인한다. 경로가 비었거나 파일이 없으면 `IllegalStateException`으로 **기동이 실패한다.** 조용히 넘어가지 않는 것이 의도다

| 키 | 어디에 | 커밋 |
| --- | --- | --- |
| `private.pem` | **저장소 밖.** auth만 갖는다. 경로만 주입한다 | **절대 금지** |
| `public.pem` | `sp-member`·`sp-board`의 `src/main/resources/jwt-public.pem` | 가능 |

**운영 키는 개발 키와 분리한다.** 운영 개인키는 시크릿 저장소에서 파일로 마운트하고 그 경로를 준다.

**공개키 배포 지점이 member·board 두 곳이다.** 두 사본이 같은 키인지는 통합 검증 I-01에서 확인한다. 키를 다시 만들면 기존 토큰이 전부 무효가 되어 재로그인이 필요하다.
