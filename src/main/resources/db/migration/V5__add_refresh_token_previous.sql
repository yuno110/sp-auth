-- 정본: sp-docs/domain-model.md §2.2 (previous_token·rotated_at), sp-docs/requirements/member.md §6.3
-- 버전 번호는 계획이 배정했다 (sp-docs/plan/phase1.md §2.4, D-17)
--
-- 재발급의 재사용 유예에 쓴다. 회전이 성공하면 같은 UPDATE 가 previous_token 에 제시된
-- 토큰을, rotated_at 에 회전 시각을 넣는다. 로그인은 둘을 비운다. 그래서 둘 다 NULL 을 허용한다.
--
-- previous_token 에 CHARACTER SET 절을 쓰지 않는다. 테이블 기본 문자셋을 물려받게 해서
-- token 과 같은 ascii 가 된다 — V4 의 CONVERT TO CHARACTER SET ascii 가 테이블 기본값도 바꿨다.
-- 컬럼 단위 CHARACTER SET 절은 H2(MySQL 모드)가 구문 오류로 거부한다(V4 의 주석, 정본 §2.2 의 표).
--
-- rotated_at 은 DATETIME(6) 이다. 10초 판정의 입력이라 초로 자르지 않는다 — 앱이 마이크로초로
-- 잘라 넣는다(MySQL 은 6자리를 넘는 소수부를 반올림한다).
--
-- 두 컬럼에 인덱스를 두지 않는다. 재발급·로그아웃 모두 account_id 로 행을 찾는다 (정본 §2.2).
ALTER TABLE refresh_token ADD COLUMN previous_token VARCHAR(1024) NULL;

ALTER TABLE refresh_token ADD COLUMN rotated_at DATETIME(6) NULL;
