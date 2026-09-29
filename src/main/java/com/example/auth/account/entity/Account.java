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

	/** 로그인·재발급이 검사한다 (sp-docs/requirements/member.md §3 규칙 5). */
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
