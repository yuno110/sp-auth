package com.example.auth.account.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 링크 토큰 — 이메일 인증과 비밀번호 재설정. 정본: sp-docs/domain-model.md §2.4, 규칙은
 * sp-docs/requirements/member.md §11.1.
 *
 * <p><b>행 하나가 메일 하나의 링크다.</b> 원문은 저장하지 않는다 — {@code tokenHash} 는 토큰
 * 문자열(UTF-8)의 SHA-256 소문자 hex 다. DB 가 유출돼도 살아 있는 링크를 만들 수 없게 한다.
 *
 * <p>{@code BaseTimeEntity} 를 상속하지 않고 {@code updated_at} 이 없다 — 갱신할 것이 사용 시각뿐이다.
 * 세 시각은 감사가 아니라 앱 시계의 값을 <b>초로 잘라</b> 넣는다(sp-docs/domain-model.md §1.1).
 *
 * <p><b>사용 처리는 이 엔터티를 갱신해서 하지 않는다.</b> 조건부 UPDATE
 * ({@code AccountTokenRepository.consume(...)}) 하나가 판정한다 — 읽고 확인한 뒤 쓰면 같은 토큰의
 * 동시 확인 둘이 모두 성공한다 (sp-docs/requirements/member.md §11.1). 그래서 {@code usedAt} 을 쓰는
 * 메서드를 두지 않는다.
 */
@Getter
@Entity
@Table(name = "account_token")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AccountToken {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	/** {@code account.id} 를 가리킨다. 같은 서비스 안이므로 FK 제약을 둔다 ({@code fk_account_token_account}). */
	@Column(name = "account_id", nullable = false)
	private Long accountId;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 20)
	private TokenPurpose purpose;

	/** 토큰 문자열(UTF-8)의 SHA-256 소문자 hex. 확인은 받은 문자열을 같은 방식으로 해시해 찾는다. */
	@Column(name = "token_hash", nullable = false, length = 64, unique = true)
	private String tokenHash;

	/** 발급 시각 + 수명. 이 시각부터 만료다 — 사용 처리가 {@code expires_at > now} 를 조건에 넣는다. */
	@Column(name = "expires_at", nullable = false)
	private LocalDateTime expiresAt;

	/** 확인이 쓴 시각. NULL 이면 아직 쓰이지 않았다. */
	@Column(name = "used_at")
	private LocalDateTime usedAt;

	/** 발급 시각. */
	@Column(name = "created_at", nullable = false, updatable = false)
	private LocalDateTime createdAt;

	private AccountToken(Long accountId, TokenPurpose purpose, String tokenHash,
			LocalDateTime createdAt, LocalDateTime expiresAt) {
		this.accountId = accountId;
		this.purpose = purpose;
		this.tokenHash = tokenHash;
		this.createdAt = createdAt;
		this.expiresAt = expiresAt;
	}

	/**
	 * 발급한 토큰의 행을 만든다. 저장은 호출자가 한다.
	 *
	 * <p>발급 시각과 만료 시각을 앱 시계의 값으로 정하고 <b>둘 다 초로 자른다</b>. 그래서 수명은
	 * 발급 순간부터 최대 1초 짧을 수 있고 길어지지 않는다 (sp-docs/domain-model.md §2.4).
	 *
	 * <p>같은 계정·같은 목적의 앞 행을 지우는 것은 이 메서드가 아니라 발급하는 쪽의 일이다
	 * ({@code AccountTokenRepository.deleteByAccountIdAndPurpose(...)}).
	 *
	 * @param tokenHash 토큰 문자열(UTF-8)의 SHA-256 소문자 hex
	 * @param lifetime 목적의 수명 (sp-docs/requirements/member.md §11.1)
	 */
	public static AccountToken issue(Long accountId, TokenPurpose purpose, String tokenHash,
			Duration lifetime, Clock clock) {
		LocalDateTime now = LocalDateTime.now(clock);
		return new AccountToken(accountId, purpose, tokenHash,
				now.truncatedTo(ChronoUnit.SECONDS),
				now.plus(lifetime).truncatedTo(ChronoUnit.SECONDS));
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof AccountToken other)) {
			return false;
		}
		return this.id != null && this.id.equals(other.id);
	}

	@Override
	public int hashCode() {
		return Objects.hashCode(this.id);
	}

}
