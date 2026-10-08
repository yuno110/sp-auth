package com.example.auth.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.Objects;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Refresh Token. 정본: sp-docs/domain-model.md §2.2.
 *
 * <p><b>계정당 1행이다</b> ({@code uk_refresh_account_id}). 재로그인 시 갱신한다.
 *
 * <p>{@code BaseTimeEntity} 를 상속하지 않는다 — 정본의 컬럼 목록에 {@code created_at}·
 * {@code updated_at} 이 없다. 만료 시각은 {@code expires_at} 이 갖는다.
 *
 * <p><b>회전(rotation)은 이 엔티티를 갱신해서 하지 않는다.</b> 조건부 UPDATE 로
 * {@code RefreshTokenRepository.rotate(...)} 가 처리한다. 읽고 나서 쓰는 방식은 탈퇴와
 * 겹칠 때 삭제된 행을 되살린다 (sp-docs/requirements/member.md §6).
 */
@Getter
@Entity
@Table(name = "refresh_token")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	/** {@code account.id} 를 가리킨다. 같은 서비스 안이므로 FK 제약을 둔다 (정본 §2.2). */
	@Column(name = "account_id", nullable = false, unique = true)
	private Long accountId;

	/**
	 * 발급된 JWT 원문. <b>길이 1024 는 측정값이다</b> — 이 서비스가 발급하는 토큰이 541~557자라
	 * 512 로는 들어가지 않는다 (sp-docs/domain-model.md §2.2 의 측정표, AU-03R).
	 *
	 * <p>문자셋(ascii)은 JPA 로 선언할 수 없고 마이그레이션이 정한다
	 * ({@code V4__widen_refresh_token.sql}). 스키마의 출처는 Flyway 하나다.
	 */
	@Column(nullable = false, length = 1024, unique = true)
	private String token;

	@Column(name = "expires_at", nullable = false)
	private LocalDateTime expiresAt;

	@Builder
	private RefreshToken(Long accountId, String token, LocalDateTime expiresAt) {
		this.accountId = accountId;
		this.token = token;
		this.expiresAt = expiresAt;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof RefreshToken other)) {
			return false;
		}
		return this.id != null && this.id.equals(other.id);
	}

	@Override
	public int hashCode() {
		return Objects.hashCode(this.id);
	}

}
