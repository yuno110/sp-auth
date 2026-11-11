package com.example.auth.support;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

/**
 * 테스트가 바꿔 끼우는 앱 시계. 고정하지 않으면 시스템 시계를 따른다.
 *
 * <p>재사용 유예의 10초 경계를 벽시계를 기다리지 않고 보기 위해 쓴다
 * (sp-docs/plan/phase1.md D-17 의 검증 표 — "시계를 주입할 수 있게 하는 것은 구현 몫이다").
 * {@code Thread.sleep} 으로 우회하지 않는다.
 */
public final class MutableClock extends Clock {

	private final ZoneId zone = ZoneId.systemDefault();

	private volatile Instant fixed;

	/** 이 시각에 멈춘다. {@link #reset()} 전까지 그대로다. */
	public void set(LocalDateTime now) {
		this.fixed = now.atZone(this.zone).toInstant();
	}

	/** 시스템 시계로 돌아간다. */
	public void reset() {
		this.fixed = null;
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
		Instant now = this.fixed;
		return (now != null) ? now : Instant.now();
	}

}
