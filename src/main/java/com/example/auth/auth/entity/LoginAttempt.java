package com.example.auth.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 로그인 잠금의 카운터. 정본: sp-docs/domain-model.md §2.5, 규칙은 sp-docs/requirements/member.md §12.
 *
 * <p><b>{@code account} 를 참조하지 않는다.</b> 키는 계정이 아니라 로그인 요청의 이메일이다 — 없는
 * 이메일도 똑같이 잠겨야 잠금이 계정의 존재를 알려주지 않는다. 그래서 FK 도 없다.
 *
 * <p>{@code BaseTimeEntity} 를 상속하지 않는다. {@code updated_at} 은 감사가 아니라 판정하는 코드가
 * 앱 시계의 값을 <b>초로 잘라</b> 넣는다 — 24시간 판정과 오래된 행의 정리가 그 값을 쓴다.
 *
 * <p><b>카운터는 이 엔터티를 갱신해서 바꾸지 않는다.</b> 정본 §2.5 의 갱신 문장(조건부 UPDATE)이
 * 바꾼다 — 읽고 비교한 뒤 쓰면 동시 실패가 증가를 잃는다 (sp-docs/requirements/member.md §12.2).
 * 그래서 필드를 바꾸는 메서드를 두지 않는다.
 */
@Getter
@Entity
@Table(name = "login_attempt")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class LoginAttempt {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	/**
	 * {@link #emailKeyOf(String)} 로 만든 키. 컬럼의 문자셋·콜레이션이 {@code account.email} 과 같아야
	 * 한다 — 그것은 마이그레이션이 정한다({@code V8__create_login_attempt.sql}).
	 */
	@Column(name = "email_key", nullable = false, length = 100, unique = true)
	private String emailKey;

	/** 연속 실패 수. */
	@Column(name = "failed_count", nullable = false)
	private int failedCount;

	/** 이 시각 전이면 잠겼다. NULL 이면 잠기지 않았다. */
	@Column(name = "locked_until")
	private LocalDateTime lockedUntil;

	/** 마지막으로 바뀐 시각. */
	@Column(name = "updated_at", nullable = false)
	private LocalDateTime updatedAt;

	private LoginAttempt(String emailKey, int failedCount, LocalDateTime updatedAt) {
		this.emailKey = emailKey;
		this.failedCount = failedCount;
		this.updatedAt = updatedAt;
	}

	/**
	 * 그 키의 첫 실패 행을 만든다. 정본 §2.5 의 INSERT 가 넣는 값이다 —
	 * {@code (email_key, failed_count, locked_until, updated_at) = (:key, 1, NULL, :now)}. 저장은
	 * 호출자가 한다. 같은 키의 행이 이미 있으면 저장이 {@code uk_login_attempt_email_key} 에 걸린다.
	 *
	 * <p>{@code updated_at} 은 앱 시계의 값을 초로 자른 것이다 (sp-docs/domain-model.md §1.1·§2.5).
	 *
	 * @param emailKey {@link #emailKeyOf(String)} 로 만든 키
	 */
	public static LoginAttempt firstFailure(String emailKey, Clock clock) {
		return new LoginAttempt(emailKey, 1, LocalDateTime.now(clock).truncatedTo(ChronoUnit.SECONDS));
	}

	/**
	 * 로그인 이메일을 잠금 키로 바꾼다. <b>ASCII 대문자({@code A}~{@code Z})만 소문자로 바꾸고 나머지
	 * 글자는 그대로 둔다</b> (sp-docs/requirements/member.md §12.1). 그래서 키는 입력과 길이가 같다.
	 *
	 * <p><b>{@link String#toLowerCase} 를 쓰지 않는다.</b> 그것은 {@code Locale} 에 따라 비ASCII 를
	 * 바꾸거나 늘린다 — U+0130 {@code İ} 는 {@code Locale.ROOT} 에서 {@code i} + U+0307 이 된다. 그러면
	 * 계정 조회가 같은 계정으로 보는 입력이 콜레이션도 다르게 보는 키가 되어 한 계정의 카운터가
	 * 갈라지고, 그만큼 잠금을 피한다. ASCII 밖의 표기는 키 컬럼의 콜레이션이 계정 조회와 같은 기준으로
	 * 합친다 (sp-docs/domain-model.md §2.5).
	 *
	 * <p>키를 만드는 쪽이 모두 같은 변환을 쓰도록 변환을 이 메서드 한 곳에 둔다.
	 */
	public static String emailKeyOf(String email) {
		char[] chars = email.toCharArray();
		for (int i = 0; i < chars.length; i++) {
			char c = chars[i];
			if (c >= 'A' && c <= 'Z') {
				chars[i] = (char) (c + ('a' - 'A'));
			}
		}
		return new String(chars);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof LoginAttempt other)) {
			return false;
		}
		return this.id != null && this.id.equals(other.id);
	}

	@Override
	public int hashCode() {
		return Objects.hashCode(this.id);
	}

}
