package com.example.auth.auth.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.auth.entity.LoginAttempt;
import com.example.auth.support.MutableClock;
import com.example.auth.support.RecordingStatementInspector;
import java.time.LocalDateTime;
import java.util.regex.Pattern;
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
 * <p>AU-18 이 실패 세기의 두 문장({@code incrementFailure}·{@code lockIfReached})을 더했다. 그 문장들의 테스트는 문장의
 * 인자를 리터럴로 준다 — 한도·잠금 시간·24시간을 고르는 것은 카운터 빈({@code LoginAttemptService})의 일이고 그 값은
 * {@code AuthServiceTest} 가 본다.
 *
 * <p>{@code JpaConfig} 를 올리지 않는다 — {@code login_attempt} 는 감사 컬럼을 쓰지 않고 이 테스트는
 * 감사 대상 엔터티를 저장하지 않는다 (sp-docs/conventions.md §9.3).
 *
 * <p>Hibernate 가 준비한 SQL 을 적는 기록기({@link RecordingStatementInspector})를 이 컨텍스트에 단다 — 증가 문장의 SET
 * 순서를 SQL 로 본다.
 *
 * <p><b>H2 는 데이터를 대소문자를 구분해 비교한다</b> (sp-docs/requirements/member.md §12.2). 키 컬럼의
 * 콜레이션이 계정 조회와 같은 기준으로 키를 합치는지는 여기서 보이지 않는다 — 실 MySQL 측정의 몫이다.
 */
@DataJpaTest(properties = "spring.jpa.properties.hibernate.session_factory.statement_inspector="
		+ "com.example.auth.support.RecordingStatementInspector")
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

	// --- AU-18 실패 세기 (sp-docs/domain-model.md §2.5 「실패를 센다」) ---

	@Test
	@DisplayName("증가 — 잠기지 않은 행은 failed_count 가 하나 늘고 updated_at 이 판정 시각이 된다. 다른 키는 그대로다")
	void 증가는_잠기지_않은_행을_하나_늘린다() {
		String target = LoginAttempt.emailKeyOf("au18-increment@example.com");
		String other = LoginAttempt.emailKeyOf("au18-increment-other@example.com");
		LocalDateTime earlier = NOW.minusMinutes(3);
		행을_심는다(target, 2, null, earlier);
		행을_심는다(other, 2, null, earlier);

		int updated = this.loginAttemptRepository.incrementFailure(target, NOW, NOW.minusHours(24));

		assertThat(updated).isEqualTo(1);
		행이_이렇다(target, 3, null, NOW);
		행이_이렇다(other, 2, null, earlier);
	}

	/**
	 * 갱신 문장의 조건은 {@code updated_at <= :now - 24h} 다(sp-docs/domain-model.md §2.5, 규칙은
	 * sp-docs/requirements/member.md §12.2) — 마지막 실패가 정확히 24시간 전이면 1부터, 그보다 1초 뒤면 이어서 센다.
	 */
	@Test
	@DisplayName("증가 — 마지막 실패가 windowStart 이하이면 1부터, 그보다 1초 뒤면 이어서 센다")
	void 증가의_24시간_경계() {
		String atWindow = LoginAttempt.emailKeyOf("au18-window-at@example.com");
		String insideWindow = LoginAttempt.emailKeyOf("au18-window-inside@example.com");
		LocalDateTime windowStart = NOW.minusHours(24);
		행을_심는다(atWindow, 4, null, windowStart);
		행을_심는다(insideWindow, 4, null, windowStart.plusSeconds(1));

		assertThat(this.loginAttemptRepository.incrementFailure(atWindow, NOW, windowStart)).isEqualTo(1);
		assertThat(this.loginAttemptRepository.incrementFailure(insideWindow, NOW, windowStart)).isEqualTo(1);

		행이_이렇다(atWindow, 1, null, NOW);
		행이_이렇다(insideWindow, 5, null, NOW);
	}

	/**
	 * 잠긴 행({@code locked_until > now})은 바꾸지 않는다 — 잠긴 동안의 시도는 세지 않고 잠금을 늘리지 않는다
	 * (sp-docs/requirements/member.md §12.1). {@code locked_until} 이 판정 시각과 같으면 풀린 것이다.
	 */
	@Test
	@DisplayName("증가 — 잠긴 행은 0행이고 그대로다. locked_until 이 판정 시각과 같으면 풀린 것이라 센다. 행이 없으면 0행이다")
	void 증가는_잠긴_행을_바꾸지_않는다() {
		String locked = LoginAttempt.emailKeyOf("au18-increment-locked@example.com");
		String expiresNow = LoginAttempt.emailKeyOf("au18-increment-expires-now@example.com");
		LocalDateTime lockedAt = NOW.minusMinutes(14);
		행을_심는다(locked, 0, NOW.plusSeconds(1), lockedAt);
		행을_심는다(expiresNow, 0, NOW, lockedAt);

		assertThat(this.loginAttemptRepository.incrementFailure(locked, NOW, NOW.minusHours(24))).isZero();
		assertThat(this.loginAttemptRepository.incrementFailure(expiresNow, NOW, NOW.minusHours(24))).isEqualTo(1);
		assertThat(this.loginAttemptRepository.incrementFailure(
				LoginAttempt.emailKeyOf("au18-increment-no-row@example.com"), NOW, NOW.minusHours(24)))
				.as("행이 없는 키").isZero();

		행이_이렇다(locked, 0, NOW.plusSeconds(1), lockedAt);
		행이_이렇다(expiresNow, 1, NOW, NOW);
	}

	/**
	 * MySQL 은 한 테이블 UPDATE 의 대입을 대개 왼쪽부터 하고 뒤의 식이 앞에서 바뀐 값을 읽는다(MySQL 8.0 Reference
	 * Manual 의 UPDATE 문). {@code updated_at} 이 먼저면 {@code CASE} 가 새 시각을 읽어 24시간 조건이 늘 거짓이 된다. H2
	 * 에서는 SET 의 순서를 바꿔도 {@link #증가의_24시간_경계()} 가 통과한다(AU-18 실측) — 그래서 순서를 결과가 아니라
	 * Hibernate 가 준비한 SQL 로 본다.
	 */
	@Test
	@DisplayName("증가 문장은 failed_count 를 updated_at 보다 먼저 대입한다")
	void 증가_문장의_대입_순서() {
		String key = LoginAttempt.emailKeyOf("au18-set-order@example.com");
		행을_심는다(key, 1, null, NOW.minusMinutes(1));
		Pattern incrementUpdate = Pattern.compile("(?is)^\\s*update\\s+login_attempt\\b.*\\bfailed_count\\s*=\\s*case\\b");

		RecordingStatementInspector.clear();
		this.loginAttemptRepository.incrementFailure(key, NOW, NOW.minusHours(24));

		assertThat(RecordingStatementInspector.statements())
				.filteredOn(sql -> incrementUpdate.matcher(sql).find())
				.as("증가 문장")
				.singleElement()
				.satisfies(sql -> assertThat(sql)
						.as("SET 의 첫 대입이 failed_count 이고 updated_at 의 대입이 그 뒤다")
						.containsPattern("(?is)\\bset\\s+(\\w+\\.)?failed_count\\s*=\\s*case\\b.*\\bend\\s*,\\s*"
								+ "(\\w+\\.)?updated_at\\s*=\\s*\\?\\s+where\\b"));
	}

	/**
	 * 정본의 조건은 {@code failed_count >= 5} 다. 잠그면서 카운터를 0 으로 하고 {@code updated_at} 을 판정 시각으로 한다
	 * (sp-docs/domain-model.md §2.5). 한도는 인자로 받는다 — 여기서는 리터럴 5 다.
	 */
	@Test
	@DisplayName("잠금 — failed_count 가 한도 이상이면 잠그고 0 으로, 한도 미만이면 0행이다. 다른 키는 그대로다")
	void 잠금_문장() {
		String reached = LoginAttempt.emailKeyOf("au18-lock-reached@example.com");
		String below = LoginAttempt.emailKeyOf("au18-lock-below@example.com");
		String other = LoginAttempt.emailKeyOf("au18-lock-other@example.com");
		LocalDateTime earlier = NOW.minusMinutes(2);
		LocalDateTime lockedUntil = NOW.plusMinutes(15);
		행을_심는다(reached, 5, null, earlier);
		행을_심는다(below, 4, null, earlier);
		행을_심는다(other, 5, null, earlier);

		assertThat(this.loginAttemptRepository.lockIfReached(reached, 5, NOW, lockedUntil)).isEqualTo(1);
		assertThat(this.loginAttemptRepository.lockIfReached(below, 5, NOW, lockedUntil)).isZero();
		assertThat(this.loginAttemptRepository.lockIfReached(
				LoginAttempt.emailKeyOf("au18-lock-no-row@example.com"), 5, NOW, lockedUntil))
				.as("행이 없는 키").isZero();

		행이_이렇다(reached, 0, lockedUntil, NOW);
		행이_이렇다(below, 4, null, earlier);
		행이_이렇다(other, 5, null, earlier);
	}

	/** 행 하나를 값 그대로 SQL 로 넣는다 — 실패를 세는 경로를 거치지 않고 이 테스트가 행의 상태를 정한다. */
	private void 행을_심는다(String key, int failedCount, LocalDateTime lockedUntil, LocalDateTime updatedAt) {
		this.em.getEntityManager()
				.createNativeQuery("insert into login_attempt (email_key, failed_count, locked_until, updated_at) "
						+ "values (:key, :failedCount, :lockedUntil, :updatedAt)")
				.setParameter("key", key)
				.setParameter("failedCount", failedCount)
				.setParameter("lockedUntil", lockedUntil)
				.setParameter("updatedAt", updatedAt)
				.executeUpdate();
		this.em.clear();
	}

	/** 그 키의 행을 DB 에서 다시 읽어 세 값을 본다. */
	private void 행이_이렇다(String key, int failedCount, LocalDateTime lockedUntil, LocalDateTime updatedAt) {
		this.em.clear();
		LoginAttempt row = this.loginAttemptRepository.findByEmailKey(key).orElseThrow();
		assertThat(row.getFailedCount()).as("%s failed_count", key).isEqualTo(failedCount);
		assertThat(row.getLockedUntil()).as("%s locked_until", key).isEqualTo(lockedUntil);
		assertThat(row.getUpdatedAt()).as("%s updated_at", key).isEqualTo(updatedAt);
	}

	/**
	 * 잠긴 행을 만든다. 잠그는 문장({@code lockIfReached})을 거치지 않고 첫 실패 행을 넣은 뒤 SQL 로 두 컬럼을 채운다 —
	 * 행의 상태를 이 테스트가 정한다.
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
