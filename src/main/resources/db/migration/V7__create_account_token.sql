-- 정본: sp-docs/domain-model.md §2.4 (컬럼), §2.3 (제약·인덱스 이름), §7 (auth 의 account_token 줄)
-- 버전 번호는 계획이 배정했다 (sp-docs/plan/phase2-auth-member.md §2)
--
-- 이메일 인증과 비밀번호 재설정의 링크 토큰이다. 행 하나가 메일 하나의 링크다.
--   token_hash: 토큰 문자열(UTF-8)의 SHA-256 소문자 hex. 원문은 저장하지 않는다
--   purpose:    enum 의 이름 (EMAIL_VERIFICATION | PASSWORD_RESET). Enum 컬럼은 VARCHAR(20) 이다 (정본 §1.2)
--   used_at:    확인이 쓴 시각. NULL 이면 아직 쓰이지 않았다
--
-- updated_at 이 없다. 갱신할 것이 사용 시각뿐이라 BaseTimeEntity 를 쓰지 않는다 (정본 §2.4).
-- 세 시각은 앱이 앱 시계의 값을 초로 잘라 넣는다.
--
-- 인덱스를 CREATE TABLE 안에 선언한다. idx_account_token_account_purpose 가 FK 인덱스를 겸한다
-- (정본 §2.3). MySQL 은 FK 의 컬럼이 앞에 오는 인덱스가 없을 때만 FK 용 인덱스를 따로 만들고,
-- 그렇게 만든 인덱스는 나중에 대신할 인덱스가 생기면 지울 수 있다고 적는다. 같은 문장에 두면
-- 그 판단이 끼어들 자리가 없다.
CREATE TABLE account_token
(
    id         BIGINT      NOT NULL AUTO_INCREMENT,
    account_id BIGINT      NOT NULL,
    purpose    VARCHAR(20) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    expires_at DATETIME    NOT NULL,
    used_at    DATETIME    NULL,
    created_at DATETIME    NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uk_account_token_hash UNIQUE (token_hash),
    -- 같은 계정·같은 목적의 앞 토큰 지우기
    INDEX idx_account_token_account_purpose (account_id, purpose),
    -- 만료 행의 주기 삭제
    INDEX idx_account_token_expires_at (expires_at),
    -- account 는 같은 스키마(sp_auth)이므로 FK 를 둔다 (정본 §2.4)
    CONSTRAINT fk_account_token_account FOREIGN KEY (account_id) REFERENCES account (id)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;
