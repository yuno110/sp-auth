-- 정본: sp-docs/domain-model.md §2.1 (email_verified_at), §7 (auth 의 account 줄)
-- 버전 번호는 계획이 배정했다 (sp-docs/plan/phase2-auth-member.md §2)
--
-- 이메일 인증 시각이다. NULL 이면 미인증이다. 감사 시각이 아니다 — 인증 확인과 비밀번호 재설정
-- 확인이 앱 시계의 값을 초로 잘라 채우고, 이미 채워져 있으면 덮지 않는다 (정본 §2.1).
--
-- 컬럼 추가와 채움을 한 파일에 둔다. 정본 §7 이 "같은 마이그레이션에서 그때의 행 전부를
-- created_at 으로 채운다" 고 정했다 — 그 전에 만든 계정(V3 의 ADMIN seed 포함)은 인증된 것으로
-- 소급하고, 이 마이그레이션 뒤에 만든 계정은 NULL 로 시작한다.
--
-- UPDATE 에 WHERE 가 없는 것이 의도다. 이 시점의 행 전부가 대상이다.
ALTER TABLE account ADD COLUMN email_verified_at DATETIME NULL;

UPDATE account SET email_verified_at = created_at;
