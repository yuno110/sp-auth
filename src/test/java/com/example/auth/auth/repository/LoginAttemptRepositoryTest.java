package com.example.auth.auth.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.auth.entity.LoginAttempt;
import com.example.auth.support.MutableClock;
import com.example.auth.support.RecordingStatementInspector;
import java.time.LocalDateTime;
import java.util.Locale;
import java.util.regex.Pattern;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.data.jpa.repository.Query;
import org.springframework.test.context.ActiveProfiles;

/**
 * sp-docs/plan/phase2-auth-member.md §3 AU-12 의 "검증" 표 중 {@code login_attempt} 와 잠금 키 변환
 * 쪽이다. 정본은 sp-docs/domain-model.md §2.5, 규칙은 sp-docs/requirements/member.md §12.
 *
 * <p>실패를 세는 문장은 AU-23 이 정본 §2.5 의 1) 한 문장 upsert({@code countFailure})로 바꿨다 — AU-18 의 두 문장(증가와
 * 잠금)을 대신한다. 그 테스트는 문장의 인자를 리터럴로 준다 — 한도·잠금 시간·24시간을 고르는 것은 카운터
 * 빈({@code LoginAttemptService})의 일이고 그 값은 {@code AuthServiceTest} 가 본다.
 *
 * <p>{@code JpaConfig} 를 올리지 않는다 — {@code login_attempt} 는 감사 컬럼을 쓰지 않고 이 테스트는
 * 감사 대상 엔터티를 저장하지 않는다 (sp-docs/conventions.md §9.3).
 *
 * <p>Hibernate 가 준비한 SQL 을 적는 기록기({@link RecordingStatementInspector})를 이 컨텍스트에 단다 — 세는 문장을 정본과
 * SQL 로 대조한다. H2(MySQL 모드)는 모든 SET 식이 옛 값을 읽어 MySQL 의 왼쪽 대입과 다르므로 SET 의 순서와
 * {@code updated_at} 의 조건은 결과로 드러나지 않는다(정본 §2.5).
 *
 * <p><b>세는 문장에 대는 잠긴 행은 잠그는 문장이 만든 모양으로 심는다</b> — {@code failed_count} 0,
 * {@code updated_at = locked_until - 15m}. 세는 문장은 잠긴 행의 {@code failed_count} 에 0 을, 같은 초에 잠긴 행의
 * {@code updated_at} 에 {@code :now} 를 쓰므로 그 밖의 모양은 정본대로 구현해도 「그대로」 가 아니다(정본 §2.5 의
 * 「1) 의 뜻」).
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
	 * (sp-docs/requirements/member.md §12.1). 첫 실패 행은 세는 문장(정본 §2.5 의 1))이 넣는다.
	 */
	@Test
	@DisplayName("100자 email_key 가 세는 문장으로 저장되고 키로 읽힌다 — 첫 실패 행은 (1, NULL, now) 다")
	void 최대_길이_키가_저장된다() {
		String key = LoginAttempt.emailKeyOf("A".repeat(88) + "@EXAMPLE.COM");
		assertThat(key).as("픽스처 — 100자 키").hasSize(100);

		센다(key);

		assertThat(this.loginAttemptRepository.findByEmailKey(key).orElseThrow().getEmailKey()).isEqualTo(key);
		행이_이렇다(key, 1, null, NOW);
	}

	/** 세는 문장이 기대는 UNIQUE 다 — 그 키의 충돌을 갱신으로 바꾼다(정본 §2.5). 같은 키의 둘째 INSERT 는 제약 위반이다. */
	@Test
	@DisplayName("email_key 가 같은 둘째 INSERT 는 uk_login_attempt_email_key 의 제약 위반이다")
	void 같은_키의_둘째_INSERT_는_제약_위반이다() {
		String key = LoginAttempt.emailKeyOf("dup-key@example.com");
		행을_심는다(key, 1, null, NOW);

		assertThatThrownBy(() -> 행을_심는다(key, 1, null, NOW))
				.isInstanceOf(ConstraintViolationException.class)
				.hasMessageContaining("uk_login_attempt_email_key");
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
		행을_심는다(target, 3, lockedUntil, NOW);
		행을_심는다(other, 3, lockedUntil, NOW);
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
	 * (sp-docs/domain-model.md §1.1). 쓰는 쪽이 초로 자르지 않으면 이 H2 테스트에서 소수부가 남는다. 세는 문장은 판정
	 * 시각을 인자로 받고 그 값을 자르는 것은 카운터 빈이다 — 그쪽은 {@code AuthServiceTest} 가 본다.
	 */
	@Test
	@DisplayName("소수부가 있는 시계로 쓴 updated_at 은 저장값에 소수부가 없다 — 잠금 해제")
	void 시각은_초로_잘려_저장된다() {
		String key = LoginAttempt.emailKeyOf("fraction@example.com");
		행을_심는다(key, 1, null, NOW);

		this.clock.set(NOW.plusMinutes(1).withNano(300_000_000));
		this.loginAttemptRepository.reset(key, this.clock);

		LocalDateTime reset = this.loginAttemptRepository.findByEmailKey(key).orElseThrow().getUpdatedAt();
		assertThat(reset).isEqualTo(NOW.plusMinutes(1));
		assertThat(reset.getNano()).isZero();
	}

	// --- AU-23 실패를 세는 한 문장 upsert (sp-docs/domain-model.md §2.5 「실패를 센다」 의 1)) ---

	/**
	 * AU-23 검증표 「세는 문장의 SQL — 정본과 대조한다」. 정본 §2.5 의 1) 을 그대로 옮겨 적고, 정본이 식으로 적은 값만 이
	 * 문장의 인자 이름으로 바꾼 것이 {@code @Query} 의 문장과 같아야 한다 — 공백과 대소문자만 가리지 않는다. Hibernate 가
	 * 준비한 SQL 도 그 문장의 인자 자리만 {@code ?} 로 바뀐 것이다.
	 *
	 * <p>정본 사본은 sp-docs dc551de 의 domain-model §2.5 에서 옮겼다. 정본이 바뀌면 이 사본도 고친다.
	 *
	 * <p>결과를 보는 H2 테스트는 SET 의 순서와 {@code updated_at} 의 조건 {@code locked_until <> :now + 15m …} 을 보지
	 * 못한다 — H2 는 모든 SET 식이 옛 값을 읽는다. 둘 다 MySQL 에서만 뜻이 바뀐다(정본 §2.5). 그래서 문장을 정본과 대조한다.
	 */
	@Test
	@DisplayName("세는 문장은 정본 §2.5 의 1) 과 식까지 같다 — SET 은 locked_until, failed_count, updated_at 순서다")
	void 세는_문장은_정본과_같다() throws NoSuchMethodException {
		String canonical = """
				INSERT INTO login_attempt (email_key, failed_count, locked_until, updated_at)
				     VALUES (:key, 1, NULL, :now)
				     ON DUPLICATE KEY UPDATE
				       locked_until = CASE WHEN locked_until > :now THEN locked_until
				                           WHEN (CASE WHEN updated_at <= :now - 24h THEN 1 ELSE failed_count + 1 END) >= 5
				                                THEN :now + 15m
				                           ELSE locked_until END,
				       failed_count = CASE WHEN locked_until > :now THEN 0
				                           WHEN updated_at <= :now - 24h THEN 1
				                           WHEN failed_count + 1 >= 5 THEN 0
				                           ELSE failed_count + 1 END,
				       updated_at   = CASE WHEN locked_until > :now
				                                AND (locked_until <> :now + 15m OR updated_at = :now) THEN updated_at
				                           ELSE :now END
				""";
		String expected = 문장을_고른다(canonical
				.replace(":key", ":emailKey")
				.replace(":now - 24h", ":windowStart")
				.replace(":now + 15m", ":lockedUntil")
				.replace(">= 5", ">= :threshold"));
		String declared = LoginAttemptRepository.class
				.getMethod("countFailure", String.class, LocalDateTime.class, LocalDateTime.class, int.class,
						LocalDateTime.class)
				.getAnnotation(Query.class)
				.value();

		assertThat(문장을_고른다(declared)).as("@Query 의 문장").isEqualTo(expected);

		Pattern upsert = Pattern.compile(
				"(?is)^\\s*insert\\s+into\\s+login_attempt\\b.*\\bon\\s+duplicate\\s+key\\s+update\\b");
		RecordingStatementInspector.clear();
		센다(LoginAttempt.emailKeyOf("au23-statement@example.com"));

		assertThat(RecordingStatementInspector.statements())
				.filteredOn(sql -> upsert.matcher(sql).find())
				.as("Hibernate 가 준비한 세는 문장")
				.singleElement()
				.satisfies(sql -> assertThat(문장을_고른다(sql)).isEqualTo(expected.replaceAll(":[A-Za-z]+", "?")));
	}

	@Test
	@DisplayName("넷째 실패 — failed_count 4, updated_at = now, 잠그지 않는다. 다른 키는 그대로다")
	void 넷째_실패는_4_로_센다() {
		String target = LoginAttempt.emailKeyOf("au23-fourth@example.com");
		String other = LoginAttempt.emailKeyOf("au23-fourth-other@example.com");
		LocalDateTime earlier = NOW.minusMinutes(3);
		행을_심는다(target, 3, null, earlier);
		행을_심는다(other, 3, null, earlier);

		센다(target);

		행이_이렇다(target, 4, null, NOW);
		행이_이렇다(other, 3, null, earlier);
	}

	/**
	 * 한도 판정이 문장 안에 있다. H2 는 모든 SET 식이 옛 값을 읽으므로 {@code failed_count} 식은 셋째 줄
	 * ({@code failed_count + 1 >= 5 THEN 0})로 간다 — 그 줄이 없으면 5 인 채 잠긴다(2026-11-23 프로브, 정본 §2.5).
	 */
	@Test
	@DisplayName("다섯째 실패 — locked_until = now + 15m, failed_count 0, updated_at = now")
	void 다섯째_실패는_잠그고_0_으로_한다() {
		String key = LoginAttempt.emailKeyOf("au23-fifth@example.com");
		행을_심는다(key, 4, null, NOW.minusMinutes(1));

		센다(key);

		행이_이렇다(key, 0, NOW.plusMinutes(15), NOW);
	}

	/**
	 * 잠긴 동안의 시도는 세지 않고 잠금을 늘리지 않는다(sp-docs/requirements/member.md §12.1). 잠긴 행은 잠그는 문장이 만든
	 * 모양이다 — 5분 전에 잠겨 {@code updated_at = locked_until - 15m}. {@code updated_at} 이 판정 시각이 아니므로 잠긴 행에
	 * {@code :now} 를 쓰면 드러난다.
	 */
	@Test
	@DisplayName("잠긴 행 — 행의 모든 컬럼이 그대로다(updated_at 포함)")
	void 잠긴_행은_그대로다() {
		String key = LoginAttempt.emailKeyOf("au23-locked@example.com");
		LocalDateTime lockedAt = NOW.minusMinutes(5);
		행을_심는다(key, 0, lockedAt.plusMinutes(15), lockedAt);

		센다(key);

		행이_이렇다(key, 0, lockedAt.plusMinutes(15), lockedAt);
	}

	/**
	 * 같은 판정 시각에 다른 시도가 막 잠근 행 — 문장은 이 행을 이번 시도가 막 잠근 행으로 읽어 {@code updated_at} 에
	 * {@code :now} 를 쓰지만 그 값이 이미 {@code :now} 다(정본 §2.5).
	 */
	@Test
	@DisplayName("같은 판정 시각에 막 잠긴 행(0, now + 15m, now) — 그대로다")
	void 같은_초에_잠긴_행은_그대로다() {
		String key = LoginAttempt.emailKeyOf("au23-locked-same-second@example.com");
		행을_심는다(key, 0, NOW.plusMinutes(15), NOW);

		센다(key);

		행이_이렇다(key, 0, NOW.plusMinutes(15), NOW);
	}

	/**
	 * 창의 조건은 {@code updated_at <= :now - 24h} 다(sp-docs/domain-model.md §2.5, 규칙은 sp-docs/requirements/member.md
	 * §12.2) — 정확히 24시간 전이면 1부터 센다. 넷이 쌓인 행이라 이어서 세면 잠긴다.
	 */
	@Test
	@DisplayName("창이 지난 행(4, updated_at = now - 24h) — failed_count 1, 잠기지 않는다")
	void 창이_지난_행은_1부터_센다() {
		String key = LoginAttempt.emailKeyOf("au23-window-passed@example.com");
		행을_심는다(key, 4, null, NOW.minusHours(24));

		센다(key);

		행이_이렇다(key, 1, null, NOW);
	}

	@Test
	@DisplayName("updated_at 이 now - 24h 보다 1초 뒤인 행 — 이어서 센다")
	void 창_안의_행은_이어서_센다() {
		String key = LoginAttempt.emailKeyOf("au23-window-inside@example.com");
		행을_심는다(key, 3, null, NOW.minusHours(24).plusSeconds(1));

		센다(key);

		행이_이렇다(key, 4, null, NOW);
	}

	/**
	 * {@code locked_until} 이 판정 시각과 같으면 풀린 것이다 — 잠금은 {@code locked_until > :now} 다. 그 행은 잠그는 문장이
	 * 15분 전에 만든 모양이다. 지난 잠금 시각은 문장이 바꾸지 않아 남는다(정본 §2.5 의 {@code ELSE locked_until}).
	 */
	@Test
	@DisplayName("locked_until 이 판정 시각과 같은 행 — 풀린 것으로 1부터 센다")
	void 잠금_시각의_행은_풀린_것이다() {
		String key = LoginAttempt.emailKeyOf("au23-expires-now@example.com");
		행을_심는다(key, 0, NOW, NOW.minusMinutes(15));

		센다(key);

		행이_이렇다(key, 1, NOW, NOW);
	}

	@Test
	@DisplayName("새 키 — (1, NULL, now) 를 넣는다")
	void 새_키는_1_로_넣는다() {
		String key = LoginAttempt.emailKeyOf("au23-new-key@example.com");

		센다(key);

		행이_이렇다(key, 1, null, NOW);
	}

	/**
	 * AU-21 검증표 「24시간 안·밖의 잠금 행 → 밖만 지워진다」·「지금 잠겨 있는 행 → 남는다」 의 문장 쪽
	 * (sp-docs/domain-model.md §2.5). 인자는 리터럴로 준다 — 24시간을 고르는 것은 정리 작업의 일이고 그 값은
	 * {@code AccountCleanupTest} 가 본다. 경계({@code updated_at = cutoff})의 행은 「이른」 행이 아니라 남는다.
	 */
	@Test
	@DisplayName("오래된 행 지우기 — updated_at 이 cutoff 보다 이른 행만 지우고 경계·안쪽·지금 잠긴 행은 남긴다")
	void 오래된_행만_지운다() {
		LocalDateTime cutoff = NOW.minusHours(24);
		String outside = LoginAttempt.emailKeyOf("au21-outside@example.com");
		String boundary = LoginAttempt.emailKeyOf("au21-boundary@example.com");
		String inside = LoginAttempt.emailKeyOf("au21-inside@example.com");
		String locked = LoginAttempt.emailKeyOf("au21-locked@example.com");
		행을_심는다(outside, 3, null, cutoff.minusSeconds(1));
		행을_심는다(boundary, 3, null, cutoff);
		행을_심는다(inside, 3, null, cutoff.plusSeconds(1));
		// 지금 잠겨 있는 행 — 잠그는 문장이 updated_at 을 잠근 시각으로 쓰므로 그 값은 지금에서 15분 안이다
		행을_심는다(locked, 0, NOW.plusMinutes(10), NOW.minusMinutes(5));

		// 지운 행 수는 보지 않는다 — 공유 H2 에 다른 클래스가 남긴 오래된 행이 함께 지워질 수 있다
		this.loginAttemptRepository.deleteUpdatedBefore(cutoff);
		this.em.clear();

		assertThat(this.loginAttemptRepository.findByEmailKey(outside)).as("24시간 밖").isEmpty();
		행이_이렇다(boundary, 3, null, cutoff);
		행이_이렇다(inside, 3, null, cutoff.plusSeconds(1));
		행이_이렇다(locked, 0, NOW.plusMinutes(10), NOW.minusMinutes(5));
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
	 * 정본 §2.5 의 1) 로 그 키의 실패를 하나 센다. 판정 시각은 {@link #NOW}, 창은 24시간, 한도는 5, 잠금은 15분이다 — 정본의
	 * {@code :now - 24h}·{@code 5}·{@code :now + 15m} 을 리터럴로 준다.
	 */
	private void 센다(String key) {
		this.loginAttemptRepository.countFailure(key, NOW, NOW.minusHours(24), 5, NOW.plusMinutes(15));
	}

	/** 대조하려고 문장의 공백을 하나로 접고 괄호 안쪽의 공백을 지운 뒤 소문자로 한다. */
	private static String 문장을_고른다(String sql) {
		return sql.strip()
				.replaceAll("\\s+", " ")
				.replace("( ", "(")
				.replace(" )", ")")
				.toLowerCase(Locale.ROOT);
	}

}
