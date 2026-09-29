-- 정본: sp-docs/domain-model.md §2.2 (컬럼), §2.3 (인덱스)
-- 버전 번호는 계획이 배정했다 (sp-docs/plan/phase1.md §2.4)
--
-- 계정당 1행이다 — uk_refresh_account_id 가 그것을 보장한다.
-- created_at / updated_at 은 정본에 없다. 이 테이블은 BaseTimeEntity 를 쓰지 않는다.
CREATE TABLE refresh_token
(
    id         BIGINT       NOT NULL AUTO_INCREMENT,
    account_id BIGINT       NOT NULL,
    token      VARCHAR(512) NOT NULL,
    expires_at DATETIME     NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uk_refresh_account_id UNIQUE (account_id),
    CONSTRAINT uk_refresh_token UNIQUE (token),
    -- account 는 같은 스키마(sp_auth)이므로 FK 를 둔다 (sp-docs/domain-model.md §2.2)
    CONSTRAINT fk_refresh_token_account FOREIGN KEY (account_id) REFERENCES account (id)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;
