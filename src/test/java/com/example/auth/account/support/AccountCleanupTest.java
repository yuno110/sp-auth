package com.example.auth.account.support;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.AccountToken;
import com.example.auth.account.entity.TokenPurpose;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.account.repository.AccountTokenRepository;
import com.example.auth.auth.entity.LoginAttempt;
import com.example.auth.auth.service.LoginAttemptService;
import com.example.auth.support.MutableClock;
import com.example.auth.support.TestRsaKeys;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.config.IntervalTask;
import org.springframework.scheduling.config.ScheduledTask;
import org.springframework.scheduling.config.ScheduledTaskHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.convention.TestBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

/**
 * sp-docs/plan/phase2-auth-member.md AU-21 의 완료 기준과 검증표를 정리 작업 쪽에서 본다. 정본은
 * sp-docs/domain-model.md §2.4·§2.5, sp-docs/tech-stack.md §4.7 이다. 삭제 문장의 경계는
 * {@code AccountTokenRepositoryTest}·{@code LoginAttemptRepositoryTest} 가 본다.
 *
 * <p><b>정리는 테스트가 직접 부른다</b>({@link AccountCleanup#run()}). 스케줄러는 이 컨텍스트에서 돌지 않는다 — 주기를
 * 97분으로 덮고 첫 실행도 그만큼 늦다. 97분은 운영 값(1시간)·테스트 프로파일 값(하루)과 달라서, 등록된 작업의 주기가 그
 * 설정을 읽었는지가 보인다.
 *
 * <p><b>기준 시각은 실제 시계의 열흘 뒤를 초로 자른 값이다.</b> 정리가 주입한 시계가 아니라 시스템 시계를 읽으면, 이
 * 기준으로 이미 만료된 토큰·24시간 지난 행이 실제 시계로는 아직 미래라 지워지지 않는다 — 판정 시각이 주입한 시계라는
 * 완료 기준이 그것으로 드러난다. 대신 이 기준의 정리는 공유 H2 의 다른 클래스가 남긴 행도 지운다 — 테스트는 한 JVM 에서
 * 차례로 돌므로 진행 중인 다른 테스트의 행이 아니다. <b>24시간은 리터럴로 적는다</b> — 판정의 상수를 가져다 쓰면 그 상수를
 * 바꾼 변이에서 픽스처가 함께 움직인다.
 */
@SpringBootTest(properties = "account-cleanup.interval=PT97M")
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AccountCleanupTest {

	private static final Duration 시험_주기 = Duration.ofMinutes(97);

	private static final LocalDateTime 기준 = LocalDateTime.now().plusDays(10).truncatedTo(ChronoUnit.SECONDS);

	/** 이 테스트가 만드는 이메일의 앞부분. 정리가 이것으로 이 테스트의 행만 지운다. */
	private static final String 접두 = "au21-cleanup-";

	private static final MutableClock CLOCK = new MutableClock();

	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	/** 애플리케이션의 {@code Clock} 빈을 {@link #CLOCK} 로 바꾼다 ({@code ClockConfig}). */
	@TestBean
	private Clock clock;

	static Clock clock() {
		return CLOCK;
	}

	@Autowired
	private AccountCleanup accountCleanup;

	@Autowired
	private LoginAttemptService loginAttemptService;

	@Autowired
	private AccountRepository accountRepository;

	@Autowired
	private AccountTokenRepository accountTokenRepository;

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	/** 스케줄러가 등록한 작업을 내보이는 쪽이다 — {@code @Scheduled} 를 처리하는 후처리기다. */
	@Autowired
	private List<ScheduledTaskHolder> scheduledTaskHolders;

	@AfterEach
	void 정리() {
		CLOCK.reset();
		this.jdbcTemplate.update("delete from account_token where account_id in "
				+ "(select id from account where email like ?)", 접두 + "%");
		this.jdbcTemplate.update("delete from account where email like ?", 접두 + "%");
		this.jdbcTemplate.update("delete from login_attempt where email_key like ?", 접두 + "%");
	}

	/**
	 * 완료 기준 「domain-model §2.4·§2.5 의 기준으로 지운다」·「판정 시각은 주입한 Clock 이다」 와 검증표의 앞 세 줄.
	 * 토큰은 만료 시각이 지금 이하이면 지우고, 잠금 행은 마지막으로 바뀐 시각이 지금에서 24시간보다 이르면 지운다.
	 */
	@Test
	@DisplayName("정리는 주입한 시계로 만료된 토큰과 24시간 밖의 잠금 행만 지우고, 만료 전 토큰·24시간 안·지금 잠긴 행은 남긴다")
	void 기준대로_지운다() {
		Long accountId = 계정을_만든다(접두 + "criteria@example.com");
		String expired = 토큰을_심는다(accountId, 기준.minusHours(1), Duration.ofMinutes(59).plusSeconds(59));
		String live = 토큰을_심는다(accountId, 기준.minusHours(1), Duration.ofHours(1).plusSeconds(1));
		String outside = 접두 + "outside@example.com";
		String boundary = 접두 + "boundary@example.com";
		String locked = 접두 + "locked@example.com";
		카운터를_심는다(outside, 3, null, 기준.minusHours(24).minusSeconds(1));
		카운터를_심는다(boundary, 3, null, 기준.minusHours(24));
		카운터를_심는다(locked, 0, 기준.plusMinutes(10), 기준.minusMinutes(5));

		CLOCK.set(기준);
		this.accountCleanup.run();

		assertThat(토큰_행이_있다(expired)).as("1초 전에 만료된 토큰").isFalse();
		assertThat(토큰_행이_있다(live)).as("1초 남은 토큰").isTrue();
		assertThat(카운터_행이_있다(outside)).as("24시간에서 1초 더 된 잠금 행").isFalse();
		assertThat(카운터_행이_있다(boundary)).as("꼭 24시간 된 잠금 행").isTrue();
		assertThat(카운터_행이_있다(locked)).as("지금 잠겨 있는 행").isTrue();
	}

	/**
	 * 검증표 「지운 토큰으로 확인 → 400 AU007(만료 토큰과 같다)」. 지운 토큰과, 정리 뒤에 만료되어 행이 남은 토큰을 같은
	 * 시각에 확인한다 — 둘 다 같은 응답이다 (sp-docs/domain-model.md §2.4).
	 */
	@Test
	@DisplayName("지운 토큰과 행이 남은 만료 토큰의 확인은 둘 다 400 AU007 이다")
	void 지운_토큰의_확인은_만료_토큰과_같다() throws Exception {
		Long deletedOwner = 계정을_만든다(접두 + "token-deleted@example.com");
		Long expiredOwner = 계정을_만든다(접두 + "token-expired@example.com");
		String deleted = 토큰을_심는다(deletedOwner, 기준.minusHours(2), Duration.ofHours(1));
		String expiredLater = 토큰을_심는다(expiredOwner, 기준.minusHours(2), Duration.ofHours(2).plusMinutes(30));

		CLOCK.set(기준);
		this.accountCleanup.run();
		assertThat(토큰_행이_있다(deleted)).as("픽스처 — 정리가 지운 토큰").isFalse();
		assertThat(토큰_행이_있다(expiredLater)).as("픽스처 — 정리 때는 만료 전이라 남은 토큰").isTrue();

		CLOCK.set(기준.plusHours(1));
		링크_토큰_오류다(확인(deleted));
		링크_토큰_오류다(확인(expiredLater));
		assertThat(인증_시각(deletedOwner)).isNull();
		assertThat(인증_시각(expiredOwner)).isNull();
	}

	/**
	 * 검증표 「지운 잠금 행의 이메일로 실패 → 카운터 1(24시간 지난 행과 같다)」. 정리가 지운 행의 이메일과, 정리 때는 꼭
	 * 24시간이라 남았지만 마지막 실패에서 24시간이 지난 행의 이메일로 같은 시각에 한 번씩 실패한다 (sp-docs/domain-model.md
	 * §2.5).
	 */
	@Test
	@DisplayName("지운 잠금 행의 이메일과 24시간 지난 행의 이메일의 다음 실패는 둘 다 카운터 1 이다")
	void 지운_잠금_행의_다음_실패는_1부터다() {
		String deleted = 접두 + "attempt-deleted@example.com";
		String stale = 접두 + "attempt-stale@example.com";
		카운터를_심는다(deleted, 4, null, 기준.minusHours(24).minusSeconds(1));
		카운터를_심는다(stale, 4, null, 기준.minusHours(24));

		CLOCK.set(기준);
		this.accountCleanup.run();
		assertThat(카운터_행이_있다(deleted)).as("픽스처 — 정리가 지운 행").isFalse();
		assertThat(카운터_행이_있다(stale)).as("픽스처 — 경계라 남은 행").isTrue();

		assertThat(this.loginAttemptService.countFailure(deleted)).as("잠그지 않는다").isFalse();
		assertThat(this.loginAttemptService.countFailure(stale)).as("잠그지 않는다").isFalse();

		assertThat(실패_수(deleted)).isEqualTo(1);
		assertThat(실패_수(stale)).isEqualTo(1);
	}

	/**
	 * 완료 기준 「여러 인스턴스가 각자 돌아도 결과가 같다」. 두 정리를 같은 때 돌리고(인스턴스 둘의 대역 — 같은 DB 에 각자
	 * 트랜잭션을 연다) 한 번 더 돌린다. 어느 쪽도 실패하지 않고, 남는 행이 한 번 돌린 결과와 같다.
	 */
	@Test
	@DisplayName("정리 둘이 같은 때 돌고 한 번 더 돌아도 실패하지 않고 남는 행이 한 번 돌린 것과 같다")
	void 여럿이_돌아도_결과가_같다() throws Exception {
		Long accountId = 계정을_만든다(접두 + "concurrent@example.com");
		String expired = 토큰을_심는다(accountId, 기준.minusHours(2), Duration.ofHours(1));
		String live = 토큰을_심는다(accountId, 기준.minusHours(2), Duration.ofHours(3));
		String outside = 접두 + "concurrent-outside@example.com";
		String inside = 접두 + "concurrent-inside@example.com";
		카운터를_심는다(outside, 2, null, 기준.minusHours(30));
		카운터를_심는다(inside, 2, null, 기준.minusHours(1));
		CLOCK.set(기준);

		ExecutorService pool = Executors.newFixedThreadPool(2);
		try {
			CountDownLatch start = new CountDownLatch(1);
			Future<?> first = pool.submit(() -> {
				start.await();
				this.accountCleanup.run();
				return null;
			});
			Future<?> second = pool.submit(() -> {
				start.await();
				this.accountCleanup.run();
				return null;
			});
			start.countDown();
			first.get(10, TimeUnit.SECONDS);
			second.get(10, TimeUnit.SECONDS);
		} finally {
			pool.shutdownNow();
		}
		this.accountCleanup.run();

		assertThat(토큰_행이_있다(expired)).isFalse();
		assertThat(토큰_행이_있다(live)).isTrue();
		assertThat(카운터_행이_있다(outside)).isFalse();
		assertThat(실패_수(inside)).as("남은 행은 바뀌지 않는다").isEqualTo(2);
	}

	/** 완료 기준 「주기는 account-cleanup.interval 이다」 (sp-docs/tech-stack.md §4.7). 첫 실행도 그만큼 늦다. */
	@Test
	@DisplayName("정리 작업은 account-cleanup.interval 의 주기로 스케줄러에 등록되고 첫 실행도 그만큼 늦다")
	void 설정한_주기로_등록된다() {
		String 이름 = AccountCleanup.class.getName() + ".run";
		List<ScheduledTask> 작업 = this.scheduledTaskHolders.stream()
				.flatMap(holder -> holder.getScheduledTasks().stream())
				.filter(task -> 이름.equals(task.getTask().getRunnable().toString()))
				.toList();
		assertThat(작업).as("정리 작업이 스케줄러에 하나 등록돼 있다").hasSize(1);
		assertThat(작업.get(0).getTask()).isInstanceOf(IntervalTask.class);
		IntervalTask 정리_작업 = (IntervalTask) 작업.get(0).getTask();

		assertThat(정리_작업.getIntervalDuration()).isEqualTo(시험_주기);
		assertThat(정리_작업.getInitialDelayDuration()).isEqualTo(시험_주기);
	}

	private Long 계정을_만든다(String email) {
		return this.accountRepository.saveAndFlush(Account.builder()
				.email(email)
				.password("test-not-a-hash-au21")
				.build()).getId();
	}

	/** 인증 목적의 토큰 행을 {@code issuedAt} 에 수명 {@code lifetime} 으로 심고 원문을 돌려준다. */
	private String 토큰을_심는다(Long accountId, LocalDateTime issuedAt, Duration lifetime) {
		MutableClock at = new MutableClock();
		at.set(issuedAt);
		String token = AccountTokens.generate();
		this.accountTokenRepository.saveAndFlush(AccountToken.issue(accountId, TokenPurpose.EMAIL_VERIFICATION,
				AccountTokens.hash(token), lifetime, at));
		return token;
	}

	private boolean 토큰_행이_있다(String token) {
		return this.accountTokenRepository.findByTokenHash(AccountTokens.hash(token)).isPresent();
	}

	private void 카운터를_심는다(String email, int failedCount, LocalDateTime lockedUntil, LocalDateTime updatedAt) {
		this.jdbcTemplate.update(
				"insert into login_attempt (email_key, failed_count, locked_until, updated_at) values (?, ?, ?, ?)",
				LoginAttempt.emailKeyOf(email), failedCount, lockedUntil, updatedAt);
	}

	private boolean 카운터_행이_있다(String email) {
		Integer count = this.jdbcTemplate.queryForObject(
				"select count(*) from login_attempt where email_key = ?", Integer.class, LoginAttempt.emailKeyOf(email));
		return count != null && count > 0;
	}

	private int 실패_수(String email) {
		Integer count = this.jdbcTemplate.queryForObject(
				"select failed_count from login_attempt where email_key = ?", Integer.class,
				LoginAttempt.emailKeyOf(email));
		return count == null ? -1 : count;
	}

	private LocalDateTime 인증_시각(Long accountId) {
		return this.jdbcTemplate.queryForObject(
				"select email_verified_at from account where id = ?", LocalDateTime.class, accountId);
	}

	private ResultActions 확인(String token) throws Exception {
		return this.mockMvc.perform(post("/api/v1/accounts/email-verification/confirm")
				.contentType(MediaType.APPLICATION_JSON)
				.characterEncoding(StandardCharsets.UTF_8)
				.content("{\"token\": \"" + token + "\"}"));
	}

	/** 400 {@code AU007} — 없음·만료·사용됨·목적 다름·탈퇴 계정이 이 하나다 (sp-docs/requirements/member.md §11.1). */
	private static void 링크_토큰_오류다(ResultActions result) throws Exception {
		result.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("AU007"));
	}

}
