package com.example.auth.support;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * 발송 실행기에 넘어간 일이 끝날 때까지 기다린다 — 가입이 커밋 뒤에 넘긴 인증 메일 발급 작업과, 그 작업이 자기 커밋 뒤에
 * 넘긴 발송까지 (sp-docs/requirements/member.md §11.5).
 *
 * <p><b>왜 필요한가.</b> 가입(AU-16)은 응답을 돌려준 뒤 다른 스레드에서 {@code account_token} 행을 만든다. 테스트의 정리가
 * 그보다 먼저 돌면 정리가 지운 뒤에 토큰 행이 생겨 계정 삭제가 {@code fk_account_token_account} 에 걸리고, 남은 메일이
 * 컨텍스트를 함께 쓰는 다음 테스트의 발송기에 섞인다.
 *
 * <p><b>표지 작업을 두 번 넣는다.</b> 실행기의 스레드가 하나이고 대기열이 들어온 차례대로 돌므로
 * ({@code MailExecutorConfig}) 표지가 돌았다면 그보다 먼저 넣은 작업은 끝났다. 발급 작업은 커밋한 뒤에 발송을 대기열 끝에
 * 넣으므로 첫 표지 뒤에 발송이 남을 수 있다 — 둘째 표지가 그것까지 기다린다.
 */
public final class MailExecutorDrain {

	private static final int MARKERS = 2;

	private static final long TIMEOUT_SECONDS = 10;

	private MailExecutorDrain() {
	}

	public static void drain(ThreadPoolTaskExecutor mailExecutor) {
		for (int i = 0; i < MARKERS; i++) {
			CountDownLatch ran = new CountDownLatch(1);
			mailExecutor.execute(ran::countDown);
			try {
				if (!ran.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
					throw new AssertionError("발송 실행기가 " + TIMEOUT_SECONDS + "초 안에 비지 않았다");
				}
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new AssertionError("발송 실행기를 기다리다 끊겼다", e);
			}
		}
	}

}
