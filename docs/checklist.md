# auth-service 구현 체크리스트

`AU-xx` 항목 **상태의 단일 원본**이다. 항목의 범위·완료 기준·검증은 `sp-docs/plan/phase1.md` §4의 같은 ID를 본다.

줄 형식: `- [ ] <ID> <이름> · 상태 <todo|doing|review|blocked|done> · 커밋 <해시 또는 ->`
`blocked`는 줄 끝에 `· 사유: ...`를 붙인다. 사유는 다음 작업자가 이어받을 수 있을 만큼 구체적으로 적는다.

절차는 `sp-docs/process/dev-workflow.md`를 따른다.

## 상태

| 상태 | 의미 |
| --- | --- |
| `todo` | 시작 전 |
| `doing` | 구현·테스트 중 |
| `review` | **테스트 통과, 리뷰 사이클 안** (리뷰 중이거나 수정 중) |
| `done` | 리뷰 APPROVED + 커밋·푸시 완료 |
| `blocked` | 진행 불가. 사유를 구체적으로 적는다 |

**`doing`에서 곧바로 `done`으로 가지 않는다.** 리뷰를 거치지 않은 항목은 완료가 아니다.
2라운드 이상이면 줄 끝에 `· 리뷰 2라운드`를 붙인다.

**여러 워커가 이 파일을 고칠 수 있다.** 자기 항목의 줄만 수정하고, 파일을 재정렬하거나 다른 줄을 건드리지 않는다 (`sp-docs/process/orchestration.md` §6).

## 기반 단계 (순차)

뒤의 모든 항목이 의존한다. 순서대로 진행한다.

- [x] AU-01 프로젝트 스캐폴딩 · 상태 done
- [x] AU-02 공통 기반 · 상태 done
- [x] AU-03 도메인 기반 · 상태 done
- [x] AU-03R 토큰 컬럼 폭 정정 · 상태 done

> **AU-03R이 왜 있나** — AU-03은 `done`이지만 `refresh_token.token`이 `VARCHAR(512)`인데 이 서비스가 발급하는 토큰은 541~557자다. AU-06에서 로그인이 막혀 드러났다. `phase1.md` §2.6 #2에 해당하므로 AU-03을 고치지 않고 후속 항목으로 처리한다. **`V2`를 수정하지 않는다** — 이미 적용되어 Flyway 체크섬이 깨진다.
- [x] AU-04 보안 기반 · 상태 done

## 기능 단계

기반 산출물을 읽기만 하고 자기 파일을 만든다. 기반 경로의 파일을 고쳐야 하면 BLOCKED로 보고한다.

- [x] AU-05 계정 생성과 이메일 중복 확인 · 상태 done · 리뷰 3라운드
- [x] AU-06 로그인 · 상태 done
- [ ] AU-07 토큰 재발급과 로그아웃 · 상태 todo
- [ ] AU-08 비밀번호 변경 · 상태 todo
- [ ] AU-09 계정 탈퇴 · 상태 todo
- [ ] AU-10 내 계정 조회 · 상태 todo
- [ ] AU-11 마무리 · 상태 todo

`AU-05`·`AU-08`·`AU-09`·`AU-10`이 `AccountService`·`AccountController`를 공유하고, `AU-06`·`AU-07`이 `AuthService`·`AuthController`를 공유한다. 저장소에 워커가 하나이므로 순차로 진행한다.

## 통합 검증

`I-xx`의 상태 원본은 **`sp-board`의 `docs/checklist.md`**다. 여기에 적지 않는다.

**AU-11·M-11·B-09가 모두 `done`이 된 뒤에** 시작한다.

## 선행 조건

AU-01을 시작하기 전에 아래가 준비되어야 한다. 준비되지 않았으면 `blocked`로 두고 보고한다.

- [x] **`D-01`(정본 개정)이 `done`이다** (`sp-docs/docs/checklist.md`)
- [x] MySQL 8.0 로컬 설치, `SET PERSIST time_zone='+09:00'` (`sp-docs/tech-stack.md` §4.1)
- [x] `sp_auth` 스키마 생성 (`sp-docs/tech-stack.md` §4.1)
- [x] `application-local.yml` 생성하고 MySQL 비밀번호·개인키 경로 기입 (`sp-docs/tech-stack.md` §4.3.1)
- [x] RSA 키 페어 생성, `private.pem`을 `~/keys/sp/`에 배치 (`sp-docs/tech-stack.md` §4.2)
- [x] `.gitignore`에 비밀 값 항목 등록 — AU-01에서 빌드 산출물을 추가한다
- [x] 문서 저장소 클론 (`../sp-docs`)

**`private.pem`을 저장소 안에 두지 않는다.** `.gitignore`에 넣더라도 실수 한 번이면 이력에 남는다.
