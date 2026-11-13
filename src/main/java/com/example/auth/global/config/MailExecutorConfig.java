package com.example.auth.global.config;

import java.util.concurrent.ThreadPoolExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * 메일 발송 실행기 (sp-docs/tech-stack.md §4.7, sp-docs/requirements/member.md §11.5).
 *
 * <p>발송은 요청 스레드와 따로 돈다 — SMTP 의 응답 시간이 API 의 응답 시간이 되지 않는다.
 * <b>대기열에 상한을 둔다</b>({@code mail.executor.queue-capacity}). 차면 그 작업을 버리고 WARN 을
 * 남긴다 — SMTP 가 느려질 때 메모리가 쌓이지 않는다. 버린 작업을 다시 넣지 않는다(같은 절 「실패해도 다시
 * 보내지 않는다」).
 *
 * <p>스레드는 하나다. 요청 스레드 밖에서 도는 것과 대기열의 상한은 스레드 수와 상관없이 성립하므로 가장
 * 작은 수를 쓴다.
 * <b>최대 스레드 수를 core 와 같게 둔다</b> — {@link ThreadPoolExecutor} 는 대기열이 찬 뒤에 core 를 넘는
 * 스레드를 만들므로, 최대가 core 보다 크면 대기열이 차도 버리지 않고 스레드를 늘려 받는다.
 *
 * <p><b>이 빈이 있으면 Boot 의 {@code applicationTaskExecutor} 가 만들어지지 않는다</b>
 * ({@code @ConditionalOnMissingBean(Executor.class)}, 2026-11-13 AU-14 리뷰가 Boot 3.5.16 에서 확인). 한정자
 * 없는 {@code @Async} 는 이 실행기(스레드 하나, 차면 버린다)를 고르게 되므로, 들일 때는 실행기를 따로 정한다.
 */
@Configuration
public class MailExecutorConfig {

	/** 발송 실행기의 빈 이름. 쓰는 쪽은 이 이름으로 고른다. */
	public static final String MAIL_EXECUTOR = "mailExecutor";

	/** 실행기의 스레드 이름 접두어. 로그에서 요청 스레드와 갈린다. */
	public static final String THREAD_NAME_PREFIX = "mail-";

	private static final Logger log = LoggerFactory.getLogger(MailExecutorConfig.class);

	@Bean(MAIL_EXECUTOR)
	public ThreadPoolTaskExecutor mailExecutor(@Value("${mail.executor.queue-capacity}") int queueCapacity) {
		ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
		executor.setCorePoolSize(1);
		executor.setMaxPoolSize(1);
		executor.setQueueCapacity(queueCapacity);
		executor.setThreadNamePrefix(THREAD_NAME_PREFIX);
		// 버리는 작업의 내용(메일·토큰)은 남기지 않는다 (sp-docs/security.md §12). 종료 뒤에 들어온
		// 작업도 이 처리기로 오므로 그 여부를 함께 적는다
		executor.setRejectedExecutionHandler((task, pool) -> log.warn(
				"mail task discarded: executor rejected it (queue capacity={}, shut down={})",
				queueCapacity, pool.isShutdown()));
		return executor;
	}

}
