-- 정본: sp-docs/domain-model.md §2.1 (컬럼), §2.3 (인덱스)
-- 버전 번호는 계획이 배정했다 (sp-docs/plan/phase1.md §2.4)
--
-- id 는 전역 식별자다. member.account_id / post.writer_id / comment.writer_id 가 이 값을 가리킨다.
-- 스키마 경계를 넘는 참조에는 FK 를 두지 않는다.
CREATE TABLE account
(
    -- password: BCrypt 해시 (60자). role: USER | ADMIN. deleted: 탈퇴 여부 (Soft Delete)
    id         BIGINT       NOT NULL AUTO_INCREMENT,
    email      VARCHAR(100) NOT NULL,
    password   VARCHAR(60)  NOT NULL,
    role       VARCHAR(20)  NOT NULL DEFAULT 'USER',
    deleted    BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at DATETIME     NOT NULL,
    updated_at DATETIME     NOT NULL,
    PRIMARY KEY (id),
    -- 탈퇴한 계정의 이메일 재사용을 이 UNIQUE 가 막는다 (sp-docs/requirements/member.md §3 규칙 1)
    CONSTRAINT uk_account_email UNIQUE (email)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;
