package com.example.auth.global.config;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * 메일의 발급 실행기·발송 실행기 ({@link MailExecutorConfig}, sp-docs/tech-stack.md §4.7,
 * sp-docs/requirements/member.md §11.5)와 그 작업의 형 ({@link MailExecutorTask}, sp-docs/security.md §12).
 *
 * <p>두 상한을 서로 다른 작은 수(2·3)로 띄운다. 설정값을 읽지 않거나 두 키를 바꿔 읽으면 경계가 어긋나 단언이 깨진다.
 * {@code PropertyPlaceholderAutoConfiguration} 을 함께 올려 실제 기동과 같은 placeholder 해석 규칙을 쓴다
 * ({@code JwtConfigTest} 와 같다).
 */
class MailExecutorConfigTest {

	private static final int ISSUE_CAPACITY = 2;

	private static final int SEND_CAPACITY = 3;

	/** 작업이 붙잡은 메일의 값들. WARN 과 {@code toString} 에 나오면 안 된다. */
	private static final String EMAIL = "member@example.com";

	private static final String BASE_URL = "http://localhost:3000";

	private static final String TOKEN = "Zm9vYmFyLXRva2VuLXZhbHVlLTMyYnl0ZXMtbG9uZw";

	private static final String LINK = BASE_URL + "/verify-email#token=" + TOKEN;

	private final ApplicationContextRunner runner = new ApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(PropertyPlaceholderAutoConfiguration.class))
			.withUserConfiguration(MailExecutorConfig.class)
			.withPropertyValues("mail.executor.issue.queue-capacity=" + ISSUE_CAPACITY,
					"mail.executor.send.queue-capacity=" + SEND_CAPACITY);

	@Test
	@DisplayName("두 실행기가 각자 스레드 하나·최대 하나이고 대기열 상한이 각 키의 값이다")
	void 두_실행기의_설정() {
		this.runner.run(context -> {
			ThreadPoolTaskExecutor issue = context.getBean(MailExecutorConfig.ISSUE_EXECUTOR, ThreadPoolTaskExecutor.class);
			ThreadPoolTaskExecutor send = context.getBean(MailExecutorConfig.SEND_EXECUTOR, ThreadPoolTaskExecutor.class);

			assertThat(issue).isNotSameAs(send);
			assertThat(issue.getCorePoolSize()).isOne();
			assertThat(issue.getMaxPoolSize()).isOne();
			assertThat(issue.getQueueCapacity()).isEqualTo(ISSUE_CAPACITY);
			assertThat(issue.getThreadNamePrefix()).isEqualTo(MailExecutorConfig.ISSUE_THREAD_NAME_PREFIX);
			assertThat(send.getCorePoolSize()).isOne();
			assertThat(send.getMaxPoolSize()).isOne();
			assertThat(send.getQueueCapacity()).isEqualTo(SEND_CAPACITY);
			assertThat(send.getThreadNamePrefix()).isEqualTo(MailExecutorConfig.SEND_THREAD_NAME_PREFIX);
		});
	}

	/**
	 * 스레드를 하나 잡아 둔 채 대기열을 상한까지 채우고 하나를 더 넣는다. 상한까지는 받고, 넘는 하나만 버린다 — 경계의 양쪽이다.
	 * 버리는 작업은 메일을 붙잡은 {@link MailExecutorTask} 다. WARN 이 그 종류·계정 id·목적을 적고, 붙잡은 메일의 값과
	 * 작업의 {@code toString} 을 적지 않는다. 넣는 호출은 던지지 않는다.
	 */
	@ParameterizedTest(name = "{0}, accountId={3}")
	@CsvSource({
			MailExecutorConfig.ISSUE_EXECUTOR + ", " + ISSUE_CAPACITY + ", ISSUE, ",
			MailExecutorConfig.ISSUE_EXECUTOR + ", " + ISSUE_CAPACITY + ", ISSUE, 7",
			MailExecutorConfig.SEND_EXECUTOR + ", " + SEND_CAPACITY + ", SEND, 7"
	})
	@DisplayName("대기열이 차면 그 작업을 버리고 종류·계정 id·목적을 WARN 한 줄로 남긴다. 상한까지는 받고, 던지지 않는다")
	void 대기열이_차면_버리고_WARN_한_줄을_남긴다(String beanName, int capacity, MailExecutorTask.Kind kind,
			Long accountId) {
		this.runner.run(context -> {
			ThreadPoolTaskExecutor executor = context.getBean(beanName, ThreadPoolTaskExecutor.class);
			CountDownLatch release = new CountDownLatch(1);
			막는다(executor, release);

			ListAppender<ILoggingEvent> appender = attachAppender();
			try {
				CountDownLatch queuedRan = new CountDownLatch(capacity);
				for (int i = 0; i < capacity; i++) {
					executor.execute(queuedRan::countDown);
				}
				assertThat(warnings(appender)).as("상한까지는 버리지 않는다").isEmpty();

				AtomicBoolean discardedRan = new AtomicBoolean();
				MailExecutorTask discarded = 메일을_붙잡은_작업(kind, accountId, () -> discardedRan.set(true));
				assertThatCode(() -> executor.execute(discarded)).as("처리기는 던지지 않는다").doesNotThrowAnyException();
				List<ILoggingEvent> warnings = warnings(appender);
				assertThat(warnings).hasSize(1);
				assertThat(warnings.get(0).getFormattedMessage())
						.contains("discarded", "kind=" + kind, "accountId=" + accountId, "purpose=EMAIL_VERIFICATION",
								"queue capacity=" + capacity, "shut down=false")
						.doesNotContain(EMAIL, TOKEN, "#token=", BASE_URL, discarded.toString());
				assertThat(warnings.get(0).getThrowableProxy()).isNull();

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

	@Test
	@DisplayName("작업의 형이 아니면 종류를 모른다고 적고 내용은 적지 않는다")
	void 형이_아닌_작업은_종류를_모른다고_적는다() {
		this.runner.run(context -> {
			ThreadPoolTaskExecutor executor =
					context.getBean(MailExecutorConfig.SEND_EXECUTOR, ThreadPoolTaskExecutor.class);
			CountDownLatch release = new CountDownLatch(1);
			막는다(executor, release);
			ListAppender<ILoggingEvent> appender = attachAppender();
			try {
				for (int i = 0; i < SEND_CAPACITY; i++) {
					executor.execute(() -> { });
				}
				Runnable plain = new Runnable() {
					@Override
					public void run() {
					}

					@Override
					public String toString() {
						return "plain " + EMAIL + " " + LINK;
					}
				};
				assertThatCode(() -> executor.execute(plain)).doesNotThrowAnyException();

				List<ILoggingEvent> warnings = warnings(appender);
				assertThat(warnings).hasSize(1);
				assertThat(warnings.get(0).getFormattedMessage())
						.contains("discarded", "kind=unknown", "queue capacity=" + SEND_CAPACITY)
						.doesNotContain(EMAIL, TOKEN, "#token=", BASE_URL, "accountId", "purpose");
			} finally {
				release.countDown();
				detachAppender(appender);
			}
		});
	}

	@Test
	@DisplayName("작업의 형의 toString 은 종류·계정 id·목적만 낸다 — 붙잡은 메일의 이메일·#token= 이 없다")
	void 작업의_toString_은_종류_계정_목적만_낸다() {
		MailExecutorTask send = 메일을_붙잡은_작업(MailExecutorTask.Kind.SEND, 7L, () -> { });
		MailExecutorTask issue = 메일을_붙잡은_작업(MailExecutorTask.Kind.ISSUE, null, () -> { });

		assertThat(send.toString())
				.isEqualTo("MailExecutorTask[kind=SEND, accountId=7, purpose=EMAIL_VERIFICATION]")
				.doesNotContain(EMAIL, "#token=", TOKEN, BASE_URL);
		assertThat(issue.toString())
				.isEqualTo("MailExecutorTask[kind=ISSUE, accountId=null, purpose=EMAIL_VERIFICATION]");
	}

	/** 람다가 이메일과 링크를 붙잡는다 — 실제 발송 작업이 {@code OutgoingMail} 을 붙잡는 것과 같다. */
	private static MailExecutorTask 메일을_붙잡은_작업(MailExecutorTask.Kind kind, Long accountId, Runnable then) {
		String captured = EMAIL + " " + LINK;
		Runnable work = () -> {
			if (captured.isEmpty()) {
				throw new IllegalStateException();
			}
			then.run();
		};
		return switch (kind) {
			case ISSUE -> MailExecutorTask.issue(accountId, "EMAIL_VERIFICATION", work);
			case SEND -> MailExecutorTask.send(accountId, "EMAIL_VERIFICATION", work);
		};
	}

	private static void 막는다(ThreadPoolTaskExecutor executor, CountDownLatch release) throws InterruptedException {
		CountDownLatch running = new CountDownLatch(1);
		executor.execute(() -> {
			running.countDown();
			awaitQuietly(release);
		});
		assertThat(running.await(5, SECONDS)).as("스레드가 첫 작업을 잡았다").isTrue();
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
