package com.example.auth.support;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * 메일 실행기의 스레드를 막아 둔다 — 그 실행기의 대기열에 작업이 머물거나({@link #block}), 대기열을 상한까지 채워 다음에 넣는
 * 작업이 버려지게 한다({@link #fill()}). 실행기마다 스레드가 하나라({@code MailExecutorConfig}) 그 스레드를 잡은 작업 하나로
 * 실행기 전체가 멈춘다.
 *
 * <p><b>닫으면 풀고, 채운 작업이 다 돌 때까지 기다린다.</b> 채운 작업이 대기열에 남은 채 {@link MailExecutorDrain} 의 표지를
 * 넣으면 그 표지도 버려진다. 테스트는 {@code try}-with-resources 로 연다.
 */
public final class BlockedExecutor implements AutoCloseable {

	private static final long TIMEOUT_SECONDS = 10;

	private final ThreadPoolTaskExecutor executor;

	private final CountDownLatch release = new CountDownLatch(1);

	private CountDownLatch fillers = new CountDownLatch(0);

	private BlockedExecutor(ThreadPoolTaskExecutor executor) {
		this.executor = executor;
	}

	/** 실행기의 스레드를 잡을 때까지 기다린다. */
	public static BlockedExecutor block(ThreadPoolTaskExecutor executor) throws InterruptedException {
		BlockedExecutor blocked = new BlockedExecutor(executor);
		CountDownLatch running = new CountDownLatch(1);
		executor.execute(() -> {
			running.countDown();
			try {
				blocked.release.await(TIMEOUT_SECONDS, TimeUnit.SECONDS);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		});
		if (!running.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
			throw new AssertionError("실행기의 스레드를 잡지 못했다");
		}
		return blocked;
	}

	/** 대기열의 남은 칸을 아무것도 하지 않는 작업으로 채운다. 그 뒤에 넣는 작업은 버려진다. */
	public BlockedExecutor fill() {
		int free = this.executor.getThreadPoolExecutor().getQueue().remainingCapacity();
		this.fillers = new CountDownLatch(free);
		for (int i = 0; i < free; i++) {
			this.executor.execute(this.fillers::countDown);
		}
		if (this.executor.getThreadPoolExecutor().getQueue().remainingCapacity() != 0) {
			throw new AssertionError("대기열을 채우지 못했다");
		}
		return this;
	}

	@Override
	public void close() {
		this.release.countDown();
		try {
			if (!this.fillers.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
				throw new AssertionError("채운 작업이 " + TIMEOUT_SECONDS + "초 안에 다 돌지 않았다");
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new AssertionError("채운 작업을 기다리다 끊겼다", e);
		}
	}

}
