package com.example.auth.global.ratelimit;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * 요청 수 제한기 (sp-docs/security.md §10). 인스턴스 메모리에서 센다. 저장하지 않으므로 재기동하면 카운터가 사라진다.
 *
 * <p><b>고정 창이다.</b> 주입한 {@link Clock} 의 시간대에서 잰 시각을 창의 길이로 나눈 몫이 창의 번호다 — 1분·1시간 창이 그
 * 시계의 분·시 경계에 맞는다. 배열은 창이 바뀐 뒤 그 규칙의 첫 요청이 비운다. 비우기 전에 그 배열을 읽는 요청이 없으므로
 * 경계에서 비우는 것과 같다.
 *
 * <p><b>키마다 칸을 두지 않는다.</b> 규칙마다 고정 크기의 카운터 배열을 두고 키의 HMAC-SHA256 으로 버킷을 고른다. HMAC 의
 * 키는 이 객체를 만들 때 새로 만든 무작위 비밀이다 — 필드에만 두고 설정·로그에 남기지 않는다. 같은 버킷에 떨어진 다른 키는
 * 한도를 나눈다(sp-docs/security.md §10 의 「대가」).
 *
 * <p><b>만들 때 설정을 검사한다.</b> 규칙의 설정이 빠졌거나 한도·창·버킷 수가 양수가 아니면 예외를 던져 기동이 실패한다
 * (sp-docs/plan/phase2-auth-member.md AU-19 의 「기동 가드」). 이 값들은 정본 값이라 기본값을 금하지 않으므로
 * (sp-docs/tech-stack.md §4.6) 빠짐과 잘못된 값만 본다.
 */
public class RateLimiter {

	private static final String HMAC_ALGORITHM = "HmacSHA256";

	/** HMAC 비밀의 바이트 수. 해시의 출력 길이와 같다. */
	private static final int SECRET_BYTES = 32;

	private final Clock clock;

	private final int bucketsPerRule;

	private final SecretKeySpec secret;

	private final Map<RateLimitRule, Counter> counters = new EnumMap<>(RateLimitRule.class);

	public RateLimiter(RateLimitProperties properties, Clock clock) {
		this.bucketsPerRule = requirePositive("rate-limit.buckets-per-rule", properties.bucketsPerRule());
		for (RateLimitRule rule : RateLimitRule.values()) {
			String key = "rate-limit.rules." + rule.key();
			RateLimitProperties.Rule config = (properties.rules() != null) ? properties.rules().get(rule.key()) : null;
			if (config == null) {
				throw new IllegalStateException(key + " 의 설정이 없다. 규칙마다 한도와 창을 둔다 "
						+ "(sp-docs/security.md §10, sp-docs/tech-stack.md §4.6).");
			}
			int limit = requirePositive(key + ".limit", config.limit());
			Duration window = requirePositive(key + ".window", config.window());
			this.counters.put(rule, new Counter(limit, window, this.bucketsPerRule));
		}
		this.clock = clock;
		byte[] secretBytes = new byte[SECRET_BYTES];
		new SecureRandom().nextBytes(secretBytes);
		this.secret = new SecretKeySpec(secretBytes, HMAC_ALGORITHM);
	}

	/**
	 * 그 규칙에서 키를 하나 센다. 키의 버킷이 이 창에서 이미 한도만큼 셌으면 세지 않고 던진다.
	 *
	 * @throws RateLimitExceededException 한도를 넘었다. 창이 끝날 때까지 남은 초를 싣는다
	 */
	public void consume(RateLimitRule rule, String key) {
		Counter counter = this.counters.get(rule);
		int bucket = bucketOf(key);
		Duration retryAfter;
		synchronized (counter) {
			// 시계를 잠금 안에서 읽는다 — 잠금을 늦게 얻은 요청이 앞선 창의 번호로 배열을 다시 비우지 않는다
			Duration now = localTime();
			long windowIndex = now.dividedBy(counter.window);
			if (windowIndex != counter.windowIndex) {
				Arrays.fill(counter.counts, 0);
				counter.windowIndex = windowIndex;
			}
			// 한도에 닿은 버킷은 더 세지 않는다
			if (counter.counts[bucket] < counter.limit) {
				counter.counts[bucket]++;
				return;
			}
			retryAfter = counter.window.multipliedBy(windowIndex + 1).minus(now);
		}
		throw new RateLimitExceededException(rule, roundUpToSeconds(retryAfter));
	}

	/** 키가 떨어지는 버킷. 버킷 선택을 테스트가 본다. */
	int bucketOf(String key) {
		byte[] digest = newMac().doFinal(key.getBytes(StandardCharsets.UTF_8));
		return Math.floorMod(ByteBuffer.wrap(digest).getLong(), this.bucketsPerRule);
	}

	/** {@link Mac} 은 스레드 사이에 나눠 쓸 수 없어 부를 때마다 만든다. */
	private Mac newMac() {
		try {
			Mac mac = Mac.getInstance(HMAC_ALGORITHM);
			mac.init(this.secret);
			return mac;
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(HMAC_ALGORITHM + " 를 쓸 수 없다", e);
		}
	}

	/** 주입한 시계의 시간대에서 잰 지금 — 그 시간대의 1970-01-01T00:00 부터 흐른 시간이다. */
	private Duration localTime() {
		Instant now = this.clock.instant();
		int offsetSeconds = this.clock.getZone().getRules().getOffset(now).getTotalSeconds();
		return Duration.ofSeconds(now.getEpochSecond() + offsetSeconds, now.getNano());
	}

	/**
	 * 남은 시간을 초로 올린다. 남은 시간은 언제나 0 보다 크다 — 창의 번호가 몫이라 창의 끝이 지금보다 뒤다. 그래서 올린 값은
	 * 1 이상이다 (sp-docs/security.md §10 의 「올림, 최소 1」).
	 */
	private static long roundUpToSeconds(Duration remaining) {
		return remaining.getSeconds() + ((remaining.getNano() > 0) ? 1 : 0);
	}

	private static int requirePositive(String key, Integer value) {
		if (value == null || value <= 0) {
			throw notPositive(key, value);
		}
		return value;
	}

	private static Duration requirePositive(String key, Duration value) {
		if (value == null || value.isZero() || value.isNegative()) {
			throw notPositive(key, value);
		}
		return value;
	}

	private static IllegalStateException notPositive(String key, Object value) {
		return new IllegalStateException(key + " 의 값이 없거나 양수가 아니다: " + value + " (sp-docs/tech-stack.md §4.6).");
	}

	/** 한 규칙의 카운터. 필드는 이 객체를 잠근 채로만 읽고 쓴다. */
	private static final class Counter {

		private final int limit;

		/** 창의 길이. */
		private final Duration window;

		private final int[] counts;

		/** 배열이 세고 있는 창의 번호. */
		private long windowIndex;

		private Counter(int limit, Duration window, int buckets) {
			this.limit = limit;
			this.window = window;
			this.counts = new int[buckets];
		}

	}

}
