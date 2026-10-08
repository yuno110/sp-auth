-- 정본: sp-docs/domain-model.md §2.2 ("token 길이가 1024이고 ascii인 이유 — 측정값")
-- 버전 번호는 계획이 배정했다 (sp-docs/plan/phase1.md §2.4)
--
-- 이 서비스가 발급하는 토큰은 541~557자다. VARCHAR(512) 에 들어가지 않아 로그인이
-- "Value too long for column" 으로 끊겼다 (AU-06 에서 드러났다).
--
-- V2 를 고치지 않는다. 이미 적용되어 Flyway 가 체크섬을 보관하므로 수정하면 다음 기동이
-- 실패한다 (sp-docs/plan/phase1.md §2.4).
--
-- ★ 두 문장의 순서가 중요하다. 먼저 넓히면 utf8mb4 에서 uk_refresh_token 의 키가
--   1024 * 4 = 4096 바이트가 되어 InnoDB 의 3072 바이트 한계를 넘는다. MySQL 8.0 실측:
--
--     ALTER TABLE ... MODIFY COLUMN token VARCHAR(1024) NOT NULL   (utf8mb4 상태)
--       -> ERROR 1071 (42000): Specified key was too long; max key length is 3072 bytes
--
--   ascii 로 먼저 변환하면 그 키가 1024 바이트가 되어 들어간다.
--
-- 컬럼 단위가 아니라 테이블 단위(CONVERT TO)로 변환하는 이유: 컬럼 단위 CHARACTER SET 절은
-- H2(MySQL 모드)가 구문 오류로 거부한다. 테스트가 같은 스크립트를 돌리므로
-- (sp-docs/tech-stack.md §5.3) 양쪽에서 돌아야 한다. H2 2.3.232 실측:
--
--     MODIFY COLUMN token VARCHAR(1024) CHARACTER SET ascii NOT NULL   -> Syntax error
--     ALTER COLUMN token SET DATA TYPE VARCHAR(1024) CHARACTER SET ascii -> Syntax error
--     CONVERT TO CHARACTER SET ascii                                   -> 통과
--
-- refresh_token 의 문자 컬럼은 token 하나뿐이므로 변환 범위는 §2.2 가 요구하는 것과 같다.
-- 기존 값은 base64url 과 점뿐이라 ASCII 이므로 변환에서 손실되지 않는다.
ALTER TABLE refresh_token CONVERT TO CHARACTER SET ascii;

ALTER TABLE refresh_token MODIFY COLUMN token VARCHAR(1024) NOT NULL;
