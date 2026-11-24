package com.example.auth.global.config;

import java.util.concurrent.ThreadPoolExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * 메일의 발급 실행기와 발송 실행기 (sp-docs/tech-stack.md §4.7, sp-docs/requirements/member.md §11.5).
 *
 * <p><b>둘로 나눈다</b>(2026-11-23 {@code D-28}). 발급 작업(계정 찾기·발송 상한·토큰 넣기 — DB 일만)은 발급 실행기에서,
 * 발송 작업(SMTP 에 넘기기)은 발송 실행기에서 돈다. 발급이 SMTP 의 읽기 타임아웃을 기다리는 발송 뒤에 줄을 서지 않고, 보내지
 * 않을 요청(없는 이메일의 재설정·재발송 등)은 발급 대기열의 칸만 쓴다. 메일 한 통은 두 대기열에서 한 칸씩 쓴다.
 *
 * <p>둘 다 요청 스레드와 따로 돈다 — SMTP 의 응답 시간이 API 의 응답 시간이 되지 않는다. <b>대기열마다 상한을 둔다</b>
 * ({@code mail.executor.issue.queue-capacity}, {@code mail.executor.send.queue-capacity}). 차면 그 작업을 버리고 WARN 을
 * 남긴다 — SMTP 가 느려질 때 메모리가 쌓이지 않는다. 버린 작업을 다시 넣지 않는다(같은 절 「실패해도 다시 보내지 않는다」).
 *
 * <p>스레드는 실행기마다 하나다. 요청 스레드 밖에서 도는 것과 대기열의 상한은 스레드 수와 상관없이 성립하므로 가장 작은 수를
 * 쓴다. 스레드가 하나라 각 실행기는 넣은 차례대로 돈다.
 * <b>최대 스레드 수를 core 와 같게 둔다</b> — {@link ThreadPoolExecutor} 는 대기열이 찬 뒤에 core 를 넘는 스레드를
 * 만들므로, 최대가 core 보다 크면 대기열이 차도 버리지 않고 스레드를 늘려 받는다.
 *
 * <p><b>거부 처리기는 실행기마다 하나다.</b> 작업이 {@link MailExecutorTask} 이면 그 종류·계정 id·목적과 대기열 상한·종료
 * 여부를 WARN 한 줄로 적는다. 작업의 {@code toString} 은 적지 않는다. 그 형이 아닌 작업이면 종류를 모른다고 적고 내용은
 * 적지 않는다. 던지지 않는다 — 발급 작업을 넣는 것은 요청 스레드(또는 가입의 커밋 뒤)이고 발송 작업을 넣는 것은 발급 작업의
 * 커밋 뒤라, 던지면 버림이 그 호출자의 실패가 된다.
 *
 * <p><b>이 빈들이 있으면 Boot 의 {@code applicationTaskExecutor} 가 만들어지지 않는다</b>
 * ({@code @ConditionalOnMissingBean(Executor.class)} — 2026-11-24 AU-24 리뷰가 이 두 빈으로 확인했다: Executor 빈은 두 실행기뿐이고,
 * 이 설정이 없는 대조군에서는 {@code applicationTaskExecutor} 가 생긴다).
 * {@code @Async} 를 들일 때는 실행기를 한정자로 정한다.
 */
@Configuration
public class MailExecutorConfig {

	/** 발급 실행기의 빈 이름. 쓰는 쪽은 이 이름으로 고른다. */
	public static final String ISSUE_EXECUTOR = "mailIssueExecutor";

	/** 발송 실행기의 빈 이름. 쓰는 쪽은 이 이름으로 고른다. */
	public static final String SEND_EXECUTOR = "mailSendExecutor";

	/** 발급 실행기의 스레드 이름 접두어. 로그에서 요청 스레드·발송 스레드와 갈린다. */
	public static final String ISSUE_THREAD_NAME_PREFIX = "mail-issue-";

	/** 발송 실행기의 스레드 이름 접두어. 로그에서 요청 스레드·발급 스레드와 갈린다. */
	public static final String SEND_THREAD_NAME_PREFIX = "mail-send-";

	private static final Logger log = LoggerFactory.getLogger(MailExecutorConfig.class);

	@Bean(ISSUE_EXECUTOR)
	public ThreadPoolTaskExecutor mailIssueExecutor(
			@Value("${mail.executor.issue.queue-capacity}") int queueCapacity) {
		return executor(queueCapacity, ISSUE_THREAD_NAME_PREFIX);
	}

	@Bean(SEND_EXECUTOR)
	public ThreadPoolTaskExecutor mailSendExecutor(
			@Value("${mail.executor.send.queue-capacity}") int queueCapacity) {
		return executor(queueCapacity, SEND_THREAD_NAME_PREFIX);
	}

	private static ThreadPoolTaskExecutor executor(int queueCapacity, String threadNamePrefix) {
		ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
		executor.setCorePoolSize(1);
		executor.setMaxPoolSize(1);
		executor.setQueueCapacity(queueCapacity);
		executor.setThreadNamePrefix(threadNamePrefix);
		// 종료 뒤에 들어온 작업도 이 처리기로 오므로 그 여부를 함께 적는다
		executor.setRejectedExecutionHandler((task, pool) -> discarded(task, queueCapacity, pool.isShutdown()));
		return executor;
	}

	/**
	 * 버린 작업의 WARN 한 줄. 이메일·토큰·링크는 남기지 않는다 (sp-docs/security.md §12) — 작업에서 꺼내는 것은
	 * {@link MailExecutorTask} 의 종류·계정 id·목적뿐이다.
	 */
	private static void discarded(Runnable task, int queueCapacity, boolean shutDown) {
		if (task instanceof MailExecutorTask mailTask) {
			log.warn("mail task discarded: executor rejected it "
							+ "(kind={}, accountId={}, purpose={}, queue capacity={}, shut down={})",
					mailTask.kind(), mailTask.accountId(), mailTask.purpose(), queueCapacity, shutDown);
		} else {
			log.warn("mail task discarded: executor rejected it (kind=unknown, queue capacity={}, shut down={})",
					queueCapacity, shutDown);
		}
	}

}
