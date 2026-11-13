package com.example.auth.global.config;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * 발송 실행기의 대기열 상한 ({@link MailExecutorConfig}, sp-docs/tech-stack.md §4.7,
 * sp-docs/requirements/member.md §11.5).
 *
 * <p>상한을 2 로 띄운다. 설정값을 읽지 않고 다른 수를 쓰면 경계가 어긋나 단언이 깨진다.
 * {@code PropertyPlaceholderAutoConfiguration} 을 함께 올려 실제 기동과 같은 placeholder 해석 규칙을 쓴다
 * ({@code JwtConfigTest} 와 같다).
 */
class MailExecutorConfigTest {

	private static final int CAPACITY = 2;

	private final ApplicationContextRunner runner = new ApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(PropertyPlaceholderAutoConfiguration.class))
			.withUserConfiguration(MailExecutorConfig.class)
			.withPropertyValues("mail.executor.queue-capacity=" + CAPACITY);

	/**
	 * 스레드를 하나 잡아 둔 채 대기열을 상한까지 채우고 하나를 더 넣는다. 상한까지는 받고, 넘는 하나만
	 * 버린다 — 경계의 양쪽이다.
	 */
	@Test
	@DisplayName("대기열이 차면 그 작업을 버리고 WARN 한 줄을 남긴다. 상한까지는 받는다")
	void 대기열이_차면_버리고_WARN_한_줄을_남긴다() {
		this.runner.run(context -> {
			ThreadPoolTaskExecutor executor =
					context.getBean(MailExecutorConfig.MAIL_EXECUTOR, ThreadPoolTaskExecutor.class);
			CountDownLatch running = new CountDownLatch(1);
			CountDownLatch release = new CountDownLatch(1);
			executor.execute(() -> {
				running.countDown();
				awaitQuietly(release);
			});
			assertThat(running.await(5, SECONDS)).as("스레드가 첫 작업을 잡았다").isTrue();

			ListAppender<ILoggingEvent> appender = attachAppender();
			try {
				CountDownLatch queuedRan = new CountDownLatch(CAPACITY);
				for (int i = 0; i < CAPACITY; i++) {
					executor.execute(queuedRan::countDown);
				}
				assertThat(warnings(appender)).as("상한까지는 버리지 않는다").isEmpty();

				AtomicBoolean discardedRan = new AtomicBoolean();
				executor.execute(() -> discardedRan.set(true));
				List<ILoggingEvent> warnings = warnings(appender);
				assertThat(warnings).hasSize(1);
				assertThat(warnings.get(0).getFormattedMessage())
						.contains("discarded", "queue capacity=" + CAPACITY, "shut down=false");

				release.countDown();
				assertThat(queuedRan.await(5, SECONDS)).as("대기열에 넣은 작업은 돈다").isTrue();
				// 스레드가 하나라 넣은 순서대로 돈다 — 버린 작업이 대기열에 있었다면 표지보다 먼저 돈다
				CountDownLatch marker = new CountDownLatch(1);
				executor.execute(marker::countDown);
				assertThat(marker.await(5, SECONDS)).isTrue();
				assertThat(discardedRan).as("버린 작업은 나중에도 돌지 않는다 — 다시 넣지 않는다").isFalse();
			} finally {
				release.countDown();
				detachAppender(appender);
			}
		});
	}

	private static List<ILoggingEvent> warnings(ListAppender<ILoggingEvent> appender) {
		return appender.list.stream().filter(event -> event.getLevel().isGreaterOrEqual(Level.WARN)).toList();
	}

	private static void awaitQuietly(CountDownLatch latch) {
		try {
			latch.await(10, SECONDS);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	private static ListAppender<ILoggingEvent> attachAppender() {
		ListAppender<ILoggingEvent> appender = new ListAppender<>();
		appender.start();
		((Logger) LoggerFactory.getLogger(MailExecutorConfig.class)).addAppender(appender);
		return appender;
	}

	private static void detachAppender(ListAppender<ILoggingEvent> appender) {
		((Logger) LoggerFactory.getLogger(MailExecutorConfig.class)).detachAppender(appender);
		appender.stop();
	}

}
