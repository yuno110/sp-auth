package com.example.auth.account.entity;

import com.example.auth.global.common.BaseTimeEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 계정. 정본: sp-docs/domain-model.md §2.1.
 *
 * <p><b>{@code id} 가 전역 식별자다.</b> auth-service 가 발급하고 세 서비스가 공유한다
 * ({@code member.account_id}, {@code post.writer_id}, {@code comment.writer_id}).
 *
 * <p>닉네임은 여기 없다 — member 소유다. 계정은 이메일·비밀번호·권한만 갖는다
 * (sp-docs/adr/0012-auth-as-separate-service.md).
 *
 * <p>탈퇴는 Soft Delete 다. 행이 남고 {@code uk_account_email} 이 UNIQUE 이므로 탈퇴한
 * 이메일은 재가입에 재사용되지 않는다 (sp-docs/requirements/member.md §3 규칙 1).
 */
@Getter
@Entity
@Table(name = "account")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Account extends BaseTimeEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false, length = 100, unique = true)
	private String email;

	/** BCrypt 해시. 어떤 응답에도 담지 않는다 (sp-docs/requirements/member.md §3 규칙 2). */
	@Column(nullable = false, length = 60)
	private String password;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 20)
	private Role role;

	@Column(nullable = false)
	private boolean deleted;

	/**
	 * 이메일 인증 시각. <b>NULL 이면 미인증이다</b> (sp-docs/domain-model.md §2.1).
	 *
	 * <p>감사 시각이 아니다 — {@code @LastModifiedDate} 와 무관하고 {@link #markEmailVerified(Clock)}
	 * 가 채운다. 컬럼을 더한 마이그레이션({@code V6__add_account_email_verified_at.sql})이 그때의 행을
	 * {@code created_at} 으로 채웠고, 그 뒤에 만든 계정은 NULL 로 시작한다 — 빌더가 이 값을 받지 않는다.
	 */
	@Column(name = "email_verified_at")
	private LocalDateTime emailVerifiedAt;

	@Builder
	private Account(String email, String password, Role role) {
		this.email = email;
		this.password = password;
		// 미지정이면 USER 다 (sp-docs/domain-model.md §2.1 default)
		this.role = (role != null) ? role : Role.USER;
		this.deleted = false;
	}

	/**
	 * 해시된 비밀번호로 교체한다.
	 *
	 * <p>인자는 이미 인코딩된 값이다. 여기서 해싱하지 않는다 — {@code PasswordEncoder} 는
	 * 서비스 계층이 갖는다.
	 */
	public void changePassword(String encodedPassword) {
		this.password = encodedPassword;
	}

	/** 탈퇴. 행은 남긴다 (Soft Delete). */
	public void withdraw() {
		this.deleted = true;
	}

	/**
	 * 이메일 인증을 표시한다. 인증 확인과 비밀번호 재설정 확인이 채우는 값이다
	 * (sp-docs/domain-model.md §2.1, sp-docs/requirements/member.md §11).
	 *
	 * <p><b>이미 채워져 있으면 덮지 않는다</b> — 처음 인증한 시각이 남는다. 인증을 되돌리는 메서드는
	 * 두지 않는다 — 정본에 인증을 취소하는 기능이 없다.
	 *
	 * <p>앱 시계의 값을 <b>초로 잘라</b> 넣는다. 컬럼이 {@code DATETIME} 이라 MySQL 이 소수부를
	 * 반올림하므로, 자르지 않으면 엔터티의 값과 저장값이 달라진다 (sp-docs/domain-model.md §1.1).
	 */
	public void markEmailVerified(Clock clock) {
		if (this.emailVerifiedAt == null) {
			this.emailVerifiedAt = LocalDateTime.now(clock).truncatedTo(ChronoUnit.SECONDS);
		}
	}

	/**
	 * {@code deleted} 의 반대를 읽는다. <b>검사 여부와 결론은 기능별로 다르다</b>
	 * (sp-docs/requirements/member.md §3 규칙 5).
	 */
	public boolean isActive() {
		return !this.deleted;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof Account other)) {
			return false;
		}
		return this.id != null && this.id.equals(other.id);
	}

	@Override
	public int hashCode() {
		return Objects.hashCode(this.id);
	}

}
