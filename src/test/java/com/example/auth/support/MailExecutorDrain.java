package com.example.auth.support;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * 메일 실행기에 넘어간 일이 끝날 때까지 기다린다 — 가입이 커밋 뒤에 넘긴 인증 메일 발급 작업과, 그 작업이 자기 커밋 뒤에
 * 넘긴 발송 작업까지 (sp-docs/requirements/member.md §11.5).
 *
 * <p><b>왜 필요한가.</b> 가입(AU-16)은 응답을 돌려준 뒤 다른 스레드에서 {@code account_token} 행을 만든다. 테스트의 정리가
 * 그보다 먼저 돌면 정리가 지운 뒤에 토큰 행이 생겨 계정 삭제가 {@code fk_account_token_account} 에 걸리고, 남은 메일이
 * 컨텍스트를 함께 쓰는 다음 테스트의 발송기에 섞인다.
 *
 * <p><b>발급 실행기 → 발송 실행기 차례로 표지 작업을 넣는다.</b> 실행기마다 스레드가 하나이고 대기열이 들어온 차례대로
 * 돌므로({@code MailExecutorConfig}) 표지가 돌았다면 그보다 먼저 넣은 작업은 끝났다. 발급 작업은 커밋한 뒤에 발송 작업을
 * 발송 실행기에 넣으므로, 발급 실행기의 표지가 돈 뒤에는 그 발송 작업이 이미 발송 대기열에 있다 — 발송 실행기의 표지가 그것까지
 * 기다린다.
 */
public final class MailExecutorDrain {

	private static final long TIMEOUT_SECONDS = 10;

	private MailExecutorDrain() {
	}

	public static void drain(ThreadPoolTaskExecutor issueExecutor, ThreadPoolTaskExecutor sendExecutor) {
		await(issueExecutor, "발급");
		await(sendExecutor, "발송");
	}

	/**
	 * 한 실행기만 기다린다 — 다른 실행기를 일부러 막아 둔 테스트가 쓴다(예: 발송이 붙잡힌 동안 발급 실행기가 비는지 본다).
	 * 발급 작업이 넘긴 발송 작업까지 기다리지 않는다.
	 */
	public static void drainOnly(ThreadPoolTaskExecutor executor) {
		await(executor, "그");
	}

	private static void await(ThreadPoolTaskExecutor executor, String name) {
		CountDownLatch ran = new CountDownLatch(1);
		executor.execute(ran::countDown);
		try {
			if (!ran.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
				throw new AssertionError(name + " 실행기가 " + TIMEOUT_SECONDS + "초 안에 비지 않았다");
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new AssertionError(name + " 실행기를 기다리다 끊겼다", e);
		}
	}

}
