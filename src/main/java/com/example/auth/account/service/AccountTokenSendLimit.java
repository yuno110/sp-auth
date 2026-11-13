package com.example.auth.account.service;

import com.example.auth.account.entity.TokenPurpose;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.springframework.stereotype.Component;

/**
 * 계정 id·목적마다의 발송 상한 — 시간당 3통 (sp-docs/requirements/member.md §11.5, sp-docs/security.md §10.1).
 *
 * <p><b>인스턴스 메모리다.</b> 인스턴스를 늘리면 상한이 인스턴스 수만큼 곱해지고, 재기동하면 센 것이 사라진다
 * (sp-docs/security.md §10.1).
 *
 * <p>창은 지금 시각에서 한 시간 전까지다. 시각 {@code t} 에 잡은 한 통은 {@code t + 1시간} 이 되기 전까지 센다 —
 * 그 시각이 되면 빠진다. 시각은 주입한 {@link Clock} 이다.
 *
 * <p>발급이 커밋되지 않으면 부르는 쪽이 {@link #release} 로 그 한 통을 돌려놓는다. 커밋되지 않은 발급은 메일을
 * 보내지 않으므로 보낸 수에 들지 않는다.
 */
@Component
public class AccountTokenSendLimit {

	/** 창 하나에 보낼 수 있는 수 (sp-docs/requirements/member.md §11.5). */
	static final int LIMIT = 3;

	/** 창의 길이 (sp-docs/requirements/member.md §11.5 의 「시간당」). */
	static final Duration WINDOW = Duration.ofHours(1);

	private final Clock clock;

	private final ConcurrentMap<Key, Deque<Instant>> acquired = new ConcurrentHashMap<>();

	public AccountTokenSendLimit(Clock clock) {
		this.clock = clock;
	}

	/**
	 * 상한 안이면 지금 시각으로 한 통을 잡는다.
	 *
	 * <p>창을 지난 기록은 이때 모든 키에서 버린다 — 다시 요청하지 않는 계정의 키도 그 뒤 어느 계정이든 잡을 때
	 * 맵에서 빠진다.
	 *
	 * @return 잡은 시각. 상한을 넘었으면 비어 있다
	 */
	public Optional<Instant> tryAcquire(Long accountId, TokenPurpose purpose) {
		Instant now = this.clock.instant();
		for (Key key : this.acquired.keySet()) {
			this.acquired.computeIfPresent(key, (k, times) -> orNull(withoutExpired(times, now)));
		}

		Instant[] taken = new Instant[1];
		this.acquired.compute(new Key(accountId, purpose), (key, times) -> {
			Deque<Instant> live = withoutExpired((times != null) ? times : new ArrayDeque<>(), now);
			if (live.size() < LIMIT) {
				live.addLast(now);
				taken[0] = now;
			}
			return live;
		});
		return Optional.ofNullable(taken[0]);
	}

	/** {@link #tryAcquire} 가 잡은 한 통을 돌려놓는다. 그 발급이 커밋되지 않았을 때 부른다. */
	public void release(Long accountId, TokenPurpose purpose, Instant acquiredAt) {
		this.acquired.computeIfPresent(new Key(accountId, purpose), (key, times) -> {
			times.removeLastOccurrence(acquiredAt);
			return orNull(times);
		});
	}

	/** 창을 지난 기록을 버린다 — {@code now - 1시간} 이전이거나 그 시각인 것. */
	private static Deque<Instant> withoutExpired(Deque<Instant> times, Instant now) {
		Instant windowStart = now.minus(WINDOW);
		times.removeIf(time -> !time.isAfter(windowStart));
		return times;
	}

	/** 빈 기록이면 {@code null} — {@code compute} 계열이 그 키를 맵에서 뺀다. */
	private static Deque<Instant> orNull(Deque<Instant> times) {
		return times.isEmpty() ? null : times;
	}

	private record Key(Long accountId, TokenPurpose purpose) {
	}

}
