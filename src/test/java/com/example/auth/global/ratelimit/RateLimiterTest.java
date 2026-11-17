package com.example.auth.global.ratelimit;

import static com.example.auth.global.ratelimit.RateLimitRule.CHECK_EMAIL;
import static com.example.auth.global.ratelimit.RateLimitRule.LOGIN;
import static com.example.auth.global.ratelimit.RateLimitRule.SIGNUP;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * 요청 수 제한기의 단위 테스트 (sp-docs/security.md §10, sp-docs/plan/phase2-auth-member.md AU-19 의 검증 표).
 *
 * <p>시계는 시간대를 정해 둔 테스트 시계다 — 시스템 시간대에 기대지 않는다. 분 창은 {@link RateLimitRule#CHECK_EMAIL}, 시 창은
 * {@link RateLimitRule#SIGNUP} 으로 본다.
 *
 * <p>창 경계를 보는 테스트는 창이 바뀐 뒤의 첫 요청을 한도를 채운 키와 다른 버킷의 키로 보낸다. 배열은 창이 바뀐 뒤
 * 그 규칙의 첫 요청이 비우므로, 한도를 채운 키가 그 첫 요청이면 그 요청의 버킷만 비우는 구현도 통과한다.
 */
class RateLimiterTest {

	/** 테스트가 정한 시간대. 시스템 시간대에 기대지 않는다. */
	private static final ZoneId SEOUL = ZoneId.of("Asia/Seoul");

	/** 정본의 버킷 수 (sp-docs/tech-stack.md §4.6). 서로 다른 키가 한 버킷에 떨어지는 일이 드물다. */
	private static final int BUCKETS = 16384;

	private static final LocalDateTime TEN = LocalDateTime.of(2031, 3, 4, 10, 0, 0);

	@Test
	@DisplayName("한도까지는 통과하고 한도 + 1 번째가 그 규칙의 RateLimitExceededException 이다")
	void 한도까지_통과하고_다음이_넘는다() {
		RateLimiter limiter = new RateLimiter(규칙들(BUCKETS, 3), new 시계(SEOUL, TEN));

		for (int i = 0; i < 3; i++) {
			assertThatCode(() -> limiter.consume(CHECK_EMAIL, "203.0.113.1")).as("%d 번째", i + 1).doesNotThrowAnyException();
		}
		RateLimitExceededException exceeded = 넘는다(limiter, CHECK_EMAIL, "203.0.113.1");
		assertThat(exceeded.getRule()).isEqualTo(CHECK_EMAIL);
	}

	@Test
	@DisplayName("분 창 — 창이 끝나기 1ns 전까지는 넘은 채이고, 다음 분이 되면 다른 버킷의 키가 먼저 와도 다시 한도까지 통과한다")
	void 분_창의_경계() {
		시계 clock = new 시계(SEOUL, TEN);
		RateLimiter limiter = new RateLimiter(규칙들(BUCKETS, 2), clock);
		String other = 다른_버킷의_키(limiter, "203.0.113.1");
		limiter.consume(CHECK_EMAIL, "203.0.113.1");
		limiter.consume(CHECK_EMAIL, "203.0.113.1");

		clock.set(TEN.plusMinutes(1).minusNanos(1));
		넘는다(limiter, CHECK_EMAIL, "203.0.113.1");

		clock.set(TEN.plusMinutes(1));
		// 창이 바뀐 뒤의 첫 요청 — 다른 버킷의 키다
		limiter.consume(CHECK_EMAIL, other);
		assertThatCode(() -> limiter.consume(CHECK_EMAIL, "203.0.113.1")).doesNotThrowAnyException();
		assertThatCode(() -> limiter.consume(CHECK_EMAIL, "203.0.113.1")).doesNotThrowAnyException();
		넘는다(limiter, CHECK_EMAIL, "203.0.113.1");
	}

	@Test
	@DisplayName("시 창 — 창이 끝나기 1ns 전까지는 넘은 채이고, 다음 시가 되면 다른 버킷의 키가 먼저 와도 다시 통과한다")
	void 시_창의_경계() {
		시계 clock = new 시계(SEOUL, TEN);
		RateLimiter limiter = new RateLimiter(규칙들(BUCKETS, 1), clock);
		String other = 다른_버킷의_키(limiter, "203.0.113.1");
		limiter.consume(SIGNUP, "203.0.113.1");

		clock.set(TEN.plusHours(1).minusNanos(1));
		넘는다(limiter, SIGNUP, "203.0.113.1");

		clock.set(TEN.plusHours(1));
		// 창이 바뀐 뒤의 첫 요청 — 다른 버킷의 키다
		limiter.consume(SIGNUP, other);
		assertThatCode(() -> limiter.consume(SIGNUP, "203.0.113.1")).doesNotThrowAnyException();
	}

	/**
	 * {@code Retry-After} 는 창이 끝날 때까지 남은 초의 올림이고 최소 1 이다 (sp-docs/security.md §10). 버림이면 29.8초가 29,
	 * 0.5초가 0 이 된다.
	 */
	@ParameterizedTest(name = "{0} 에 넘으면 Retry-After = {1}")
	@CsvSource({
			"10:00:00, 60",
			"10:00:30, 30",
			"10:00:30.2, 30",
			"10:00:59, 1",
			"10:00:59.5, 1",
			"10:00:59.999999999, 1"
	})
	@DisplayName("분 창의 Retry-After 는 창 끝까지 남은 초의 올림이고 최소 1 이다")
	void 분_창의_Retry_After(String time, long expected) {
		RateLimiter limiter = new RateLimiter(규칙들(BUCKETS, 1), new 시계(SEOUL, TEN.with(LocalTime.parse(time))));
		limiter.consume(CHECK_EMAIL, "203.0.113.1");

		assertThat(넘는다(limiter, CHECK_EMAIL, "203.0.113.1").getRetryAfterSeconds()).isEqualTo(expected);
	}

	@ParameterizedTest(name = "{0} 에 넘으면 Retry-After = {1}")
	@CsvSource({
			"10:00:00, 3600",
			"10:59:59.5, 1"
	})
	@DisplayName("시 창의 Retry-After 도 그 규칙의 창 끝까지다")
	void 시_창의_Retry_After(String time, long expected) {
		RateLimiter limiter = new RateLimiter(규칙들(BUCKETS, 1), new 시계(SEOUL, TEN.with(LocalTime.parse(time))));
		limiter.consume(SIGNUP, "203.0.113.1");

		assertThat(넘는다(limiter, SIGNUP, "203.0.113.1").getRetryAfterSeconds()).isEqualTo(expected);
	}

	/**
	 * 창은 주입한 시계의 시간대에서 본 분·시 경계에 맞는다 (sp-docs/security.md §10 의 「시계의 분·시 경계에 맞춘다」). UTC 와
	 * 30분 어긋난 시간대(+05:30)에서 시 경계는 그 시간대의 정시다 — UTC 의 정시로 나누면 10:59:30 의 남은 시간이 30분 30초가
	 * 되고 11:00 에 비워지지 않는다.
	 */
	@Test
	@DisplayName("창은 시계의 시간대에서 본 정시에 바뀐다 — UTC 와 30분 어긋난 시간대에서도")
	void 창은_시계의_시간대의_정시에_바뀐다() {
		시계 clock = new 시계(ZoneId.of("Asia/Kolkata"), TEN.withMinute(59).withSecond(30));
		RateLimiter limiter = new RateLimiter(규칙들(BUCKETS, 1), clock);
		String other = 다른_버킷의_키(limiter, "203.0.113.1");
		limiter.consume(SIGNUP, "203.0.113.1");

		assertThat(넘는다(limiter, SIGNUP, "203.0.113.1").getRetryAfterSeconds()).isEqualTo(30);

		clock.set(TEN.plusHours(1));
		// 창이 바뀐 뒤의 첫 요청 — 다른 버킷의 키다
		limiter.consume(SIGNUP, other);
		assertThatCode(() -> limiter.consume(SIGNUP, "203.0.113.1")).doesNotThrowAnyException();
	}

	@Test
	@DisplayName("버킷 수 1 의 제한기 — 한 키가 한도를 채우면 다른 키도 넘는다")
	void 버킷이_하나면_다른_키도_한도를_나눈다() {
		RateLimiter limiter = new RateLimiter(규칙들(1, 2), new 시계(SEOUL, TEN));
		limiter.consume(CHECK_EMAIL, "203.0.113.1");
		limiter.consume(CHECK_EMAIL, "203.0.113.1");

		넘는다(limiter, CHECK_EMAIL, "198.51.100.7");
	}

	/** 두 키가 다른 버킷에 떨어지는지는 비밀에 달렸다. 그래서 다른 버킷에 떨어진 키를 골라서 본다. */
	@Test
	@DisplayName("다른 버킷에 떨어진 키는 한도를 나누지 않는다")
	void 다른_버킷의_키는_한도를_나누지_않는다() {
		RateLimiter limiter = new RateLimiter(규칙들(BUCKETS, 1), new 시계(SEOUL, TEN));
		String key = "203.0.113.1";
		String other = 다른_버킷의_키(limiter, key);
		limiter.consume(CHECK_EMAIL, key);
		넘는다(limiter, CHECK_EMAIL, key);

		assertThatCode(() -> limiter.consume(CHECK_EMAIL, other)).doesNotThrowAnyException();
	}

	/** 키가 몇 개든 버킷은 설정한 수만큼이다 — 그 밖의 칸을 만들지 않고, 설정한 칸은 다 쓴다. */
	@Test
	@DisplayName("버킷은 0 부터 버킷 수 - 1 까지다")
	void 버킷은_설정한_수만큼이다() {
		RateLimiter limiter = new RateLimiter(규칙들(4, 1), new 시계(SEOUL, TEN));

		assertThat(IntStream.range(0, 200).mapToObj(i -> "key-" + i).map(limiter::bucketOf).collect(Collectors.toSet()))
				.as("200 개의 키가 네 버킷 중 하나를 비껴 갈 확률은 무시할 만하다")
				.containsExactlyInAnyOrder(0, 1, 2, 3);
	}

	/**
	 * 버킷을 고르는 비밀은 제한기를 만들 때마다 새로 만든다 (sp-docs/security.md §10 의 「기동마다 새로 만든 무작위 비밀」).
	 * 비밀이 상수이거나 비밀 없이 키만으로 고르면 두 제한기가 모든 키를 같은 버킷에 넣는다.
	 */
	@Test
	@DisplayName("두 제한기는 같은 키들을 다른 버킷에 넣는다 — 비밀이 만들 때마다 새것이다")
	void 비밀은_만들_때마다_새것이다() {
		Clock clock = new 시계(SEOUL, TEN);
		RateLimiter first = new RateLimiter(규칙들(BUCKETS, 1), clock);
		RateLimiter second = new RateLimiter(규칙들(BUCKETS, 1), clock);
		List<String> keys = IntStream.range(0, 64).mapToObj(i -> "203.0.113." + i).toList();

		assertThat(keys.stream().map(second::bucketOf).toList())
				.as("64 개의 키가 우연히 모두 같은 버킷에 떨어질 확률은 무시할 만하다")
				.isNotEqualTo(keys.stream().map(first::bucketOf).toList());
	}

	/**
	 * 규칙마다 한도·창이 다른 설정에서 각 규칙이 제 한도 + 1 번째에 넘고 제 창의 끝까지를 {@code Retry-After} 로 낸다. 다른
	 * 테스트의 설정은 규칙들의 한도가 같아 규칙의 설정을 바꿔 읽어도 드러나지 않는다. 시각은 그 시간대의 1970-01-01T00:00 이라
	 * 어느 창 길이로 나눠도 창의 시작이다.
	 */
	@Test
	@DisplayName("한도와 창은 그 규칙의 설정이다 — 규칙마다 다른 값에서 각자의 한도 + 1 번째가 넘고 Retry-After 가 각자의 창이다")
	void 한도와_창은_그_규칙의_설정이다() {
		RateLimitRule[] rules = RateLimitRule.values();
		Map<String, RateLimitProperties.Rule> config = new HashMap<>();
		for (int i = 0; i < rules.length; i++) {
			config.put(rules[i].key(), new RateLimitProperties.Rule(i + 1, Duration.ofMinutes(i + 1)));
		}
		RateLimiter limiter = new RateLimiter(new RateLimitProperties(BUCKETS, config),
				new 시계(SEOUL, LocalDateTime.of(1970, 1, 1, 0, 0)));

		for (int i = 0; i < rules.length; i++) {
			RateLimitRule rule = rules[i];
			for (int n = 0; n < i + 1; n++) {
				assertThatCode(() -> limiter.consume(rule, "203.0.113.1")).as("%s 의 %d 번째", rule, n + 1)
						.doesNotThrowAnyException();
			}
			assertThat(넘는다(limiter, rule, "203.0.113.1").getRetryAfterSeconds()).as("%s", rule).isEqualTo(60L * (i + 1));
		}
	}

	@Test
	@DisplayName("규칙마다 따로 센다 — 한 규칙을 넘은 키가 다른 규칙에서는 통과한다")
	void 규칙마다_따로_센다() {
		RateLimiter limiter = new RateLimiter(규칙들(BUCKETS, 1), new 시계(SEOUL, TEN));
		limiter.consume(CHECK_EMAIL, "203.0.113.1");
		넘는다(limiter, CHECK_EMAIL, "203.0.113.1");

		assertThatCode(() -> limiter.consume(LOGIN, "203.0.113.1")).doesNotThrowAnyException();
	}

	/**
	 * 버킷의 확인과 증가, 창이 바뀔 때의 비우기는 한 잠금 안에서 한다. 잠금이 없으면 두 요청이 같은 수를 읽어 하나만 셀
	 * 수 있고, 늦게 비운 요청이 앞선 요청의 수를 지울 수 있다 — 어느 쪽이든 한도보다 많이 통과한다. 올바른 구현에서 통과
	 * 수는 실행 순서와 상관없이 한도다.
	 *
	 * <p><b>잠금이 없을 때 빨개지는 것은 확률적이다</b> — 요청이 실제로 겹쳐야 드러난다. 한도는 잠금을 지운 변이로 재서
	 * 정했다(2026-11-17 AU-19, 16 논리 프로세서의 PC, 따로 띄운 JVM 열 번씩). 한도 2,000 에서도 열 번 모두 빨갰지만 한도를
	 * 넘은 통과가 4 까지 줄었고, 10,000 에서는 열 번 모두 106 이상이었다. 프로세서 수에 따라 잡는 비율이 다르다 — 같은 변이를
 * 2 프로세서로 묶으면 50 번 중 46 번, 1 프로세서로 묶으면 50 번 중 0 번 빨갰다(2026-11-17 AU-19 리뷰 2라운드 실측).
	 */
	@Test
	@DisplayName("여러 스레드가 한 키로 한도의 몇 배를 동시에 보내도 정확히 한도만큼 통과한다")
	void 동시에_보내도_한도만큼_통과한다() throws Exception {
		int threads = 8;
		int limit = 10_000;
		RateLimiter limiter = new RateLimiter(규칙들(BUCKETS, limit), new 시계(SEOUL, TEN));
		CyclicBarrier start = new CyclicBarrier(threads);
		AtomicInteger passed = new AtomicInteger();
		ExecutorService executor = Executors.newFixedThreadPool(threads);
		try {
			List<Future<?>> sent = new ArrayList<>();
			for (int t = 0; t < threads; t++) {
				// 스레드마다 한도만큼 보낸다 — 모두 합하면 한도의 스레드 수 배다
				sent.add(executor.submit(() -> {
					start.await();
					for (int i = 0; i < limit; i++) {
						try {
							limiter.consume(CHECK_EMAIL, "203.0.113.1");
							passed.incrementAndGet();
						} catch (RateLimitExceededException exceeded) {
							// 넘은 요청이다. 통과한 수만 센다
						}
					}
					return null;
				}));
			}
			for (Future<?> future : sent) {
				future.get(1, TimeUnit.MINUTES);
			}
		} finally {
			executor.shutdownNow();
		}

		assertThat(passed.get()).as("%d 스레드가 %d 번씩 보냈다", threads, limit).isEqualTo(limit);
	}

	// --- 기동 가드 (sp-docs/plan/phase2-auth-member.md AU-19 의 「기동 가드」) ---

	@ParameterizedTest(name = "{0}")
	@EnumSource(RateLimitRule.class)
	@DisplayName("규칙의 설정이 빠지면 만들어지지 않고 메시지가 그 키를 말한다")
	void 규칙이_빠지면_실패한다(RateLimitRule missing) {
		RateLimitProperties properties = 규칙들(BUCKETS, 1, rules -> rules.remove(missing.key()));

		assertThatThrownBy(() -> new RateLimiter(properties, new 시계(SEOUL, TEN)))
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("rate-limit.rules." + missing.key() + " ");
	}

	@Test
	@DisplayName("규칙이 하나도 없으면 만들어지지 않는다")
	void 규칙이_없으면_실패한다() {
		assertThatThrownBy(() -> new RateLimiter(new RateLimitProperties(BUCKETS, null), new 시계(SEOUL, TEN)))
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("rate-limit.rules.");
	}

	static Stream<Arguments> 잘못된_값() {
		return Stream.of(
				Arguments.of("buckets-per-rule = null", 잘못된_버킷_수(null), "rate-limit.buckets-per-rule"),
				Arguments.of("buckets-per-rule = 0", 잘못된_버킷_수(0), "rate-limit.buckets-per-rule"),
				Arguments.of("buckets-per-rule = -1", 잘못된_버킷_수(-1), "rate-limit.buckets-per-rule"),
				Arguments.of("limit = null", 잘못된_규칙(null, Duration.ofMinutes(1)), "rate-limit.rules.login.limit"),
				Arguments.of("limit = 0", 잘못된_규칙(0, Duration.ofMinutes(1)), "rate-limit.rules.login.limit"),
				Arguments.of("limit = -1", 잘못된_규칙(-1, Duration.ofMinutes(1)), "rate-limit.rules.login.limit"),
				Arguments.of("window = null", 잘못된_규칙(30, null), "rate-limit.rules.login.window"),
				Arguments.of("window = 0", 잘못된_규칙(30, Duration.ZERO), "rate-limit.rules.login.window"),
				Arguments.of("window = -1분", 잘못된_규칙(30, Duration.ofMinutes(-1)), "rate-limit.rules.login.window"));
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("잘못된_값")
	@DisplayName("한도·창·버킷 수가 없거나 양수가 아니면 만들어지지 않고 메시지가 그 키를 말한다")
	void 양수가_아니면_실패한다(String name, RateLimitProperties properties, String key) {
		assertThatThrownBy(() -> new RateLimiter(properties, new 시계(SEOUL, TEN)))
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining(key + " ");
	}

	private static RateLimitProperties 잘못된_버킷_수(Integer buckets) {
		return new RateLimitProperties(buckets, 규칙들(BUCKETS, 1).rules());
	}

	private static RateLimitProperties 잘못된_규칙(Integer limit, Duration window) {
		return 규칙들(BUCKETS, 1, rules -> rules.put(LOGIN.key(), new RateLimitProperties.Rule(limit, window)));
	}

	/** 그 키와 다른 버킷에 떨어지는 키. 두 키가 같은 버킷에 떨어지는지는 제한기의 비밀에 달려 고를 때마다 본다. */
	private static String 다른_버킷의_키(RateLimiter limiter, String key) {
		return IntStream.range(2, 100).mapToObj(i -> "203.0.113." + i)
				.filter(candidate -> limiter.bucketOf(candidate) != limiter.bucketOf(key))
				.findFirst()
				.orElseThrow(() -> new AssertionError("모든 키가 한 버킷에 떨어진다 — 버킷을 키로 고르지 않는다"));
	}

	private static RateLimitExceededException 넘는다(RateLimiter limiter, RateLimitRule rule, String key) {
		RateLimitExceededException exceeded =
				catchThrowableOfType(RateLimitExceededException.class, () -> limiter.consume(rule, key));
		assertThat(exceeded).as("%s 의 한도를 넘어야 한다", rule).isNotNull();
		return exceeded;
	}

	/** 모든 규칙의 한도가 같다. {@link RateLimitRule#CHECK_EMAIL}·{@link RateLimitRule#LOGIN} 은 분 창, 나머지는 시 창이다. */
	private static RateLimitProperties 규칙들(int buckets, int limit) {
		return 규칙들(buckets, limit, rules -> { });
	}

	private static RateLimitProperties 규칙들(int buckets, int limit, Consumer<Map<String, RateLimitProperties.Rule>> change) {
		Map<String, RateLimitProperties.Rule> rules = new HashMap<>();
		Arrays.stream(RateLimitRule.values()).forEach(rule -> rules.put(rule.key(), new RateLimitProperties.Rule(
				limit, (rule == CHECK_EMAIL || rule == LOGIN) ? Duration.ofMinutes(1) : Duration.ofHours(1))));
		change.accept(rules);
		return new RateLimitProperties(buckets, rules);
	}

	/** 시간대를 정해 둔 채 움직이는 시계. */
	private static final class 시계 extends Clock {

		private final ZoneId zone;

		private Instant now;

		private 시계(ZoneId zone, LocalDateTime start) {
			this.zone = zone;
			set(start);
		}

		private void set(LocalDateTime local) {
			this.now = local.atZone(this.zone).toInstant();
		}

		@Override
		public ZoneId getZone() {
			return this.zone;
		}

		@Override
		public Clock withZone(ZoneId zone) {
			throw new UnsupportedOperationException("테스트 시계는 시간대를 바꾸지 않는다");
		}

		@Override
		public Instant instant() {
			return this.now;
		}

	}

}
