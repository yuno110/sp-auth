-- 정본: sp-docs/domain-model.md §2.5 (컬럼), §2.3 (제약·인덱스 이름), §7 (auth 의 login_attempt 줄)
-- 버전 번호는 계획이 배정했다 (sp-docs/plan/phase2-auth-member.md §2)
--
-- 로그인 잠금의 카운터다. email_key 는 로그인 요청의 이메일에서 ASCII 대문자만 소문자로 바꾼
-- 값이다 (sp-docs/requirements/member.md §12.1).
--
-- FK 가 없다. 그 부재가 의도다 — 없는 이메일도 똑같이 잠겨야 하므로 account 를 참조하지 않는다
-- (정본 §2.3, §2.5).
--
-- 테이블 선언이 V1 의 account 와 같은 문자셋 선언(DEFAULT CHARSET = utf8mb4)을 쓴다. email_key 가
-- account.email 과 같은 콜레이션이 되어야 UNIQUE 가 계정 조회와 같은 기준으로 키를 합친다
-- (정본 §2.5, §7). 그래서 컬럼 단위 CHARACTER SET·COLLATE 절을 두지 않는다 — 요건은 두 선언이 같은
-- 것이고, 컬럼 단위 CHARACTER SET 절은 H2(MySQL 모드)가 거부한다(V4 의 주석). 어느 콜레이션이
-- 되는지는 서버 설정이 정하므로 두 컬럼이 같은지는 information_schema 로 확인한다.
--
-- 시각은 감사가 아니라 판정하는 코드가 앱 시계의 값을 초로 잘라 넣는다 (정본 §2.5).
CREATE TABLE login_attempt
(
    id           BIGINT       NOT NULL AUTO_INCREMENT,
    email_key    VARCHAR(100) NOT NULL,
    failed_count INT          NOT NULL DEFAULT 0,
    locked_until DATETIME     NULL,
    updated_at   DATETIME     NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uk_login_attempt_email_key UNIQUE (email_key),
    -- 오래된 행의 주기 삭제
    INDEX idx_login_attempt_updated_at (updated_at)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;
