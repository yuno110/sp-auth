package com.example.auth.auth.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.auth.entity.LoginAttempt;
import com.example.auth.support.MutableClock;
import java.time.LocalDateTime;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;

/**
 * sp-docs/plan/phase2-auth-member.md §3 AU-12 의 "검증" 표 중 {@code login_attempt} 와 잠금 키 변환
 * 쪽이다. 정본은 sp-docs/domain-model.md §2.5, 규칙은 sp-docs/requirements/member.md §12.
 *
 * <p>{@code JpaConfig} 를 올리지 않는다 — {@code login_attempt} 는 감사 컬럼을 쓰지 않고 이 테스트는
 * 감사 대상 엔터티를 저장하지 않는다 (sp-docs/conventions.md §9.3).
 *
 * <p><b>H2 는 데이터를 대소문자를 구분해 비교한다</b> (sp-docs/requirements/member.md §12.2). 키 컬럼의
 * 콜레이션이 계정 조회와 같은 기준으로 키를 합치는지는 여기서 보이지 않는다 — 실 MySQL 측정의 몫이다.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("test")
class LoginAttemptRepositoryTest {

	private static final LocalDateTime NOW = LocalDateTime.of(2026, 11, 13, 10, 0, 0);

	@Autowired
	private TestEntityManager em;

	@Autowired
	private LoginAttemptRepository loginAttemptRepository;

	private final MutableClock clock = new MutableClock();

	@BeforeEach
	void setUp() {
		this.clock.set(NOW);
	}

	/**
	 * 키 컬럼의 폭은 이메일과 같은 100자다. 키는 입력과 길이가 같으므로 100자 이메일의 키가 100자다
	 * (sp-docs/requirements/member.md §12.1). 첫 실패 행의 값은 정본 §2.5 의 INSERT 다.
	 */
	@Test
	@DisplayName("100자 email_key 가 저장되고 키로 읽힌다 — 첫 실패 행은 (1, NULL, now) 다")
	void 최대_길이_키가_저장된다() {
		String key = LoginAttempt.emailKeyOf("A".repeat(88) + "@EXAMPLE.COM");
		assertThat(key).as("픽스처 — 100자 키").hasSize(100);

		this.loginAttemptRepository.saveAndFlush(LoginAttempt.firstFailure(key, this.clock));
		this.em.clear();

		LoginAttempt stored = this.loginAttemptRepository.findByEmailKey(key).orElseThrow();
		assertThat(stored.getEmailKey()).isEqualTo(key);
		assertThat(stored.getFailedCount()).isEqualTo(1);
		assertThat(stored.getLockedUntil()).isNull();
		assertThat(stored.getUpdatedAt()).isEqualTo(NOW);
	}

	@Test
	@DisplayName("email_key 가 같은 둘째 INSERT 는 제약 위반이다")
	void 같은_키의_둘째_INSERT_는_제약_위반이다() {
		String key = LoginAttempt.emailKeyOf("dup-key@example.com");
		this.loginAttemptRepository.saveAndFlush(LoginAttempt.firstFailure(key, this.clock));
		LoginAttempt duplicate = LoginAttempt.firstFailure(key, this.clock);

		assertThatThrownBy(() -> this.loginAttemptRepository.saveAndFlush(duplicate))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	/**
	 * 두 컬럼이 함께 풀리는 것을 한 번에 보려고 대상 행의 {@code failed_count} 와 {@code locked_until}
	 * 을 둘 다 채운다. 다른 키의 행은 그대로여야 한다.
	 */
	@Test
	@DisplayName("잠금 해제 문장 — 그 키의 failed_count 가 0, locked_until 이 NULL 이 된다")
	void 잠금_해제_문장() {
		String target = LoginAttempt.emailKeyOf("locked@example.com");
		String other = LoginAttempt.emailKeyOf("other-locked@example.com");
		LocalDateTime lockedUntil = NOW.plusMinutes(15);
		잠긴_행(target, 3, lockedUntil);
		잠긴_행(other, 3, lockedUntil);
		LocalDateTime resetAt = NOW.plusMinutes(1);
		this.clock.set(resetAt);

		int updated = this.loginAttemptRepository.reset(target, this.clock);

		assertThat(updated).isEqualTo(1);
		LoginAttempt reset = this.loginAttemptRepository.findByEmailKey(target).orElseThrow();
		assertThat(reset.getFailedCount()).isZero();
		assertThat(reset.getLockedUntil()).isNull();
		assertThat(reset.getUpdatedAt()).isEqualTo(resetAt);

		LoginAttempt untouched = this.loginAttemptRepository.findByEmailKey(other).orElseThrow();
		assertThat(untouched.getFailedCount()).as("다른 키").isEqualTo(3);
		assertThat(untouched.getLockedUntil()).as("다른 키").isEqualTo(lockedUntil);

		assertThat(this.loginAttemptRepository.reset(LoginAttempt.emailKeyOf("no-row@example.com"), this.clock))
				.as("행이 없는 키는 0행이다 — 행이 없는 것과 결과가 같다 (정본 §2.5)")
				.isZero();
	}

	/**
	 * 정본의 예가 U+0130 {@code İ} 다 — {@code Locale.ROOT} 의 소문자 변환은 이것을 {@code i} + U+0307
	 * 두 글자로 늘린다 (sp-docs/requirements/member.md §12.1). 그러므로 길이도 함께 본다.
	 */
	@Test
	@DisplayName("키 변환 — ASCII 대문자는 소문자가 되고 비ASCII 는 그대로다")
	void 키_변환() {
		assertThat(LoginAttempt.emailKeyOf("User.Name+TAG@Example.COM"))
				.isEqualTo("user.name+tag@example.com");

		assertThat(LoginAttempt.emailKeyOf("@ABCDEFGHIJKLMNOPQRSTUVWXYZ["))
				.as("ASCII 대문자 범위의 양 끝(A·Z)은 바뀌고 바로 바깥(@·[)은 그대로다")
				.isEqualTo("@abcdefghijklmnopqrstuvwxyz[");

		String dottedCapitalI = "İstanbul@example.com";
		assertThat(LoginAttempt.emailKeyOf(dottedCapitalI))
				.as("U+0130 은 ASCII 가 아니므로 그대로다")
				.isEqualTo(dottedCapitalI)
				.hasSameSizeAs(dottedCapitalI);

		assertThat(LoginAttempt.emailKeyOf("ÉLODIE@EXAMPLE.COM"))
				.as("U+00C9 는 그대로, 뒤의 ASCII 대문자만 소문자로")
				.isEqualTo("Élodie@example.com");
	}

	/**
	 * 컬럼이 {@code DATETIME} 이라 MySQL 은 소수부를 반올림하고 H2 는 남긴다
	 * (sp-docs/domain-model.md §1.1). 쓰는 쪽이 초로 자르지 않으면 이 H2 테스트에서 소수부가 남는다.
	 */
	@Test
	@DisplayName("소수부가 있는 시계로 쓴 updated_at 은 저장값에 소수부가 없다 — INSERT 와 잠금 해제")
	void 시각은_초로_잘려_저장된다() {
		String key = LoginAttempt.emailKeyOf("fraction@example.com");
		this.clock.set(NOW.withNano(700_000_000));
		this.loginAttemptRepository.saveAndFlush(LoginAttempt.firstFailure(key, this.clock));
		this.em.clear();

		LocalDateTime inserted = this.loginAttemptRepository.findByEmailKey(key).orElseThrow().getUpdatedAt();
		assertThat(inserted).isEqualTo(NOW);
		assertThat(inserted.getNano()).isZero();

		this.clock.set(NOW.plusMinutes(1).withNano(300_000_000));
		this.loginAttemptRepository.reset(key, this.clock);

		LocalDateTime reset = this.loginAttemptRepository.findByEmailKey(key).orElseThrow().getUpdatedAt();
		assertThat(reset).isEqualTo(NOW.plusMinutes(1));
		assertThat(reset.getNano()).isZero();
	}

	/**
	 * 잠긴 행을 만든다. 잠그는 문장은 이 항목의 것이 아니므로(정본 §2.5 의 실패 세기) 첫 실패 행을
	 * 넣고 SQL 로 두 컬럼을 채운다.
	 */
	private void 잠긴_행(String key, int failedCount, LocalDateTime lockedUntil) {
		this.loginAttemptRepository.saveAndFlush(LoginAttempt.firstFailure(key, this.clock));
		this.em.getEntityManager()
				.createNativeQuery("update login_attempt set failed_count = :failedCount, "
						+ "locked_until = :lockedUntil where email_key = :key")
				.setParameter("failedCount", failedCount)
				.setParameter("lockedUntil", lockedUntil)
				.setParameter("key", key)
				.executeUpdate();
		this.em.clear();
	}

}
