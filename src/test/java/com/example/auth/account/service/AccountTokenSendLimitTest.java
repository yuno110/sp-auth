package com.example.auth.account.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.account.entity.TokenPurpose;
import com.example.auth.support.MutableClock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * 계정 id·목적마다의 발송 상한 — 시간당 3통 (sp-docs/requirements/member.md §11.5). 시계를 움직여 창의 경계를
 * 본다.
 */
class AccountTokenSendLimitTest {

	private static final LocalDateTime T0 = LocalDateTime.of(2026, 11, 13, 10, 0, 0);

	private static final Long ACCOUNT = 7L;

	private static final Long OTHER_ACCOUNT = 8L;

	private final MutableClock clock = new MutableClock();

	private final AccountTokenSendLimit limit = new AccountTokenSendLimit(this.clock);

	@BeforeEach
	void setUp() {
		this.clock.set(T0);
	}

	@Test
	@DisplayName("창 하나에 세 통까지 잡고 넷째는 넘친다")
	void 세_통까지_잡고_넷째는_넘친다() {
		assertThat(잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET)).isPresent();
		assertThat(잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET)).isPresent();
		assertThat(잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET)).as("셋째까지 상한 안이다").isPresent();

		assertThat(잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET)).isEmpty();
	}

	/** 한 통은 잡은 시각에서 한 시간이 되기 직전까지 세고, 그 시각에 빠진다. 경계의 양쪽을 본다. */
	@Test
	@DisplayName("잡은 시각에서 한 시간이 되면 그 한 통이 빠진다 — 그 직전까지는 센다")
	void 한_시간이_되면_빠진다() {
		this.clock.set(T0);
		잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET);
		this.clock.set(T0.plusMinutes(10));
		잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET);
		this.clock.set(T0.plusMinutes(20));
		잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET);

		this.clock.set(T0.plusHours(1).minusNanos(1));
		assertThat(잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET)).as("T0 의 한 통이 아직 창 안이다").isEmpty();

		this.clock.set(T0.plusHours(1));
		assertThat(잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET)).as("T0 의 한 통이 빠졌다")
				.contains(this.clock.instant());
		assertThat(잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET)).as("빠진 것은 그 한 통뿐이다").isEmpty();
	}

	@Test
	@DisplayName("계정 id 와 목적마다 따로 센다")
	void 계정과_목적마다_따로_센다() {
		for (int i = 0; i < AccountTokenSendLimit.LIMIT; i++) {
			잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET);
		}
		assertThat(잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET)).isEmpty();

		assertThat(잡는다(ACCOUNT, TokenPurpose.EMAIL_VERIFICATION)).as("같은 계정의 다른 목적").isPresent();
		assertThat(잡는다(OTHER_ACCOUNT, TokenPurpose.PASSWORD_RESET)).as("다른 계정의 같은 목적").isPresent();
	}

	/** 같은 시각에 잡은 세 통 중 하나를 돌려놓으면 하나만 빈다. */
	@Test
	@DisplayName("돌려놓은 한 통은 세지 않는다 — 돌려놓은 수만큼만 빈다")
	void 돌려놓은_한_통은_세지_않는다() {
		Instant acquiredAt = 잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET).orElseThrow();
		잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET);
		잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET);

		this.limit.release(ACCOUNT, TokenPurpose.PASSWORD_RESET, acquiredAt);

		assertThat(잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET)).isPresent();
		assertThat(잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET)).isEmpty();
	}

	/** 다시 요청하지 않는 계정의 키가 메모리에 남지 않는다. 다른 키를 잡을 때 창을 지난 키가 빠진다. */
	@Test
	@DisplayName("창을 지난 기록은 다른 키를 잡을 때 맵에서 빠진다")
	void 창을_지난_키는_맵에서_빠진다() {
		잡는다(ACCOUNT, TokenPurpose.PASSWORD_RESET);
		this.clock.set(T0.plus(AccountTokenSendLimit.WINDOW).minusNanos(1));
		잡는다(OTHER_ACCOUNT, TokenPurpose.PASSWORD_RESET);
		assertThat(기록()).as("ACCOUNT 의 한 통은 아직 창 안이다").hasSize(2);

		this.clock.set(T0.plus(AccountTokenSendLimit.WINDOW));
		잡는다(OTHER_ACCOUNT, TokenPurpose.EMAIL_VERIFICATION);

		assertThat(기록()).as("ACCOUNT 의 키가 빠졌다").hasSize(2);
		assertThat(기록().keySet()).noneMatch(key -> ACCOUNT.equals(ReflectionTestUtils.getField(key, "accountId")));
	}

	private Optional<Instant> 잡는다(Long accountId, TokenPurpose purpose) {
		return this.limit.tryAcquire(accountId, purpose);
	}

	private Map<?, ?> 기록() {
		return (Map<?, ?>) ReflectionTestUtils.getField(this.limit, "acquired");
	}

}
