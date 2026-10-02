-- 기본 관리자 계정. 정본: sp-docs/requirements/member.md §10.1 (값), §10.2 (비밀번호)
-- 버전 번호는 계획이 배정했다 (sp-docs/plan/phase1.md §2.4)
--
-- id 를 1 로 명시 고정한다. AUTO_INCREMENT 에 맡기면 member 의 V2__seed_admin_profile.sql 이
-- account_id 로 참조할 값이 결정적이지 않다 — 두 스키마는 서로를 조회할 수 없다 (§10.1).
-- 두 값의 일치는 통합 검증 I-01 에서 확인한다.
--
-- 비밀번호 해시는 여기에 두지 않는다. 커밋하면 공개 저장소에 ADMIN 자격증명이 남고 아무도
-- 교체하지 않은 채 배포될 수 있다 (§10.2). Flyway placeholder 로 주입하며 기본값이 없으므로
-- ADMIN_PASSWORD_HASH 없이는 마이그레이션이 실패한다.
-- 해시 생성: ./gradlew bcrypt -Ppassword=... (sp-docs/tech-stack.md §4.2.1)
INSERT INTO account (id, email, password, role, deleted, created_at, updated_at)
VALUES (1, 'admin@example.com', '${adminPasswordHash}', 'ADMIN', FALSE, NOW(), NOW());
