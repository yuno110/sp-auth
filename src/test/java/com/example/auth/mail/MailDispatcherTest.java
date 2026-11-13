package com.example.auth.mail;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.auth.global.config.MailExecutorConfig;
import com.example.auth.support.InMemoryMailer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 커밋 뒤 발송 ({@link MailDispatcher}, sp-docs/requirements/member.md §11.5).
 *
 * <p>실행기는 넘겨받은 작업을 모으기만 하는 것으로 바꿔 끼운다. 커밋 전·커밋 뒤·되돌림에서 무엇이 넘어갔는지를
 * 순서대로 셀 수 있다. 트랜잭션은 {@link AbstractPlatformTransactionManager} 를 그대로 쓰는 관리자로
 * 돈다 — 커밋이면 afterCommit 을 부르고 되돌리면 부르지 않는 규칙이 JPA 의 관리자와 같은 코드다.
 * 실제 실행기·트랜잭션으로 도는 경로는 {@code MailContextTest} 가 본다.
 */
class MailDispatcherTest {

	private static final String TOKEN = "Zm9vYmFyLXRva2VuLXZhbHVlLTMyYnl0ZXMtbG9uZw";

	private static final String LINK = "http://localhost:3000/verify-email#token=" + TOKEN;

	private static final String RECIPIENT = "member@example.com";

	private static final String SUBJECT = "이메일 인증";

	private static final String SMTP_PASSWORD = "smtp-secret-value";

	private static final OutgoingMail MAIL =
			new OutgoingMail(7L, "EMAIL_VERIFICATION", RECIPIENT, SUBJECT, "아래 링크를 연다\n" + LINK);

	private final List<Runnable> handedOver = new ArrayList<>();

	private final List<OutgoingMail> delivered = new ArrayList<>();

	private final TransactionTemplate transaction = new TransactionTemplate(new NoResourceTransactionManager());

	@Test
	@DisplayName("커밋되면 커밋 뒤에 실행기로 넘기고, 넘긴 작업이 보낸다")
	void 커밋되면_커밋_뒤에_실행기로_넘긴다() {
		MailDispatcher dispatcher = dispatcher(this.delivered::add);

		this.transaction.executeWithoutResult(status -> {
			dispatcher.sendAfterCommit(MAIL);
			assertThat(this.handedOver).as("커밋 전에는 아무것도 넘기지 않는다").isEmpty();
		});

		assertThat(this.handedOver).hasSize(1);
		assertThat(this.delivered).as("부른 스레드에서 보내지 않는다 — 넘기기만 한다").isEmpty();

		this.handedOver.get(0).run();
		assertThat(this.delivered).containsExactly(MAIL);
	}

	@Test
	@DisplayName("트랜잭션 안에서 건 발송이 되돌려지면 보내지 않는다")
	void 되돌려지면_보내지_않는다() {
		MailDispatcher dispatcher = dispatcher(this.delivered::add);

		assertThatThrownBy(() -> this.transaction.executeWithoutResult(status -> {
			dispatcher.sendAfterCommit(MAIL);
			throw new IllegalStateException("가입이 실패해 되돌린다");
		})).isInstanceOf(IllegalStateException.class);

		assertThat(this.handedOver).isEmpty();
		assertThat(this.delivered).isEmpty();
	}

	@Test
	@DisplayName("트랜잭션 밖에서 부르면 예외를 던지고 아무것도 걸지 않는다")
	void 트랜잭션_밖에서_부르면_실패한다() {
		MailDispatcher dispatcher = dispatcher(this.delivered::add);

		assertThatThrownBy(() -> dispatcher.sendAfterCommit(MAIL)).isInstanceOf(IllegalStateException.class);

		assertThat(this.handedOver).isEmpty();
		assertThat(this.delivered).isEmpty();
	}

	/**
	 * SMTP 구현이 예외를 던지는 경우다 — {@link SmtpMailer} 아래의 {@link JavaMailSender} 가 던진다. 그
	 * 예외의 메시지와 원인에 토큰·링크·받는 주소·SMTP 비밀번호를 일부러 넣는다. 로그 줄이 예외를 싣거나
	 * 메시지를 옮기면 이 단언이 깨진다.
	 */
	@Test
	@DisplayName("SMTP 발송이 실패하면 다시 보내지 않고 WARN 한 줄을 남긴다 — 그 줄에 토큰·링크·주소·비밀번호가 없다")
	void 발송이_실패하면_다시_보내지_않고_WARN_한_줄을_남긴다() {
		JavaMailSender javaMailSender = mock(JavaMailSender.class);
		doThrow(new MailSendException("rejected " + RECIPIENT + " " + LINK + " auth " + SMTP_PASSWORD,
				new IllegalStateException("token " + TOKEN)))
				.when(javaMailSender).send(any(SimpleMailMessage.class));
		MailDispatcher dispatcher = dispatcher(new SmtpMailer(javaMailSender,
				new MailSettings("no-reply@localhost", "http://localhost:3000")));
		this.transaction.executeWithoutResult(status -> dispatcher.sendAfterCommit(MAIL));

		ListAppender<ILoggingEvent> appender = attachAppender();
		try {
			assertThatCode(() -> this.handedOver.get(0).run())
					.as("실행기 안에서 예외가 새지 않는다 — 새면 로그 규칙 밖에서 스택이 남는다")
					.doesNotThrowAnyException();
		} finally {
			detachAppender(appender);
		}

		verify(javaMailSender, times(1)).send(any(SimpleMailMessage.class));
		assertThat(this.handedOver).as("다시 넘기지도 않는다 — 다시 보내지 않는다").hasSize(1);

		List<ILoggingEvent> warnings = appender.list.stream()
				.filter(event -> event.getLevel().isGreaterOrEqual(Level.WARN))
				.toList();
		assertThat(warnings).hasSize(1);
		ILoggingEvent line = warnings.get(0);
		assertThat(line.getFormattedMessage())
				.contains("accountId=7", "purpose=EMAIL_VERIFICATION", MailSendException.class.getName(),
						IllegalStateException.class.getName())
				.doesNotContain(TOKEN, LINK, RECIPIENT, SMTP_PASSWORD);
		assertThat(line.getThrowableProxy()).as("예외를 붙이면 메시지와 스택이 함께 남는다").isNull();
	}

	@Test
	@DisplayName("메일의 toString 은 받는 주소·제목·본문을 내지 않는다")
	void 메일의_toString_은_본문을_내지_않는다() {
		assertThat(MAIL.toString())
				.contains("accountId=7", "purpose=EMAIL_VERIFICATION")
				.doesNotContain(RECIPIENT, SUBJECT, TOKEN, LINK);
	}

	// --- 운영 프로파일에서 시험용 발송기가 선택되면 기동이 실패한다 (sp-docs/security.md §12) ---

	/**
	 * 운영의 배선과 같게 {@link SmtpMailer} 를 늘 함께 올린다. 시험용 발송기는 테스트 컨텍스트처럼
	 * {@code @Primary} 로 넣는다 — 그래야 「선택된 채」 다.
	 */
	private final ApplicationContextRunner selection = new ApplicationContextRunner()
			.withUserConfiguration(MailDispatcher.class, SmtpMailer.class)
			.withBean(MailExecutorConfig.MAIL_EXECUTOR, Executor.class, () -> Runnable::run)
			.withBean(JavaMailSender.class, JavaMailSenderImpl::new)
			.withBean(MailSettings.class, () -> new MailSettings("no-reply@localhost", "http://localhost:3000"));

	@Test
	@DisplayName("시험용 발송기가 선택된 채 운영 프로파일로 뜨면 기동이 실패한다")
	void 운영에서_시험용_발송기가_선택되면_실패한다() {
		this.selection.withBean(InMemoryMailer.class, InMemoryMailer::new, definition -> definition.setPrimary(true))
				.withPropertyValues("spring.profiles.active=prod")
				.run(context -> {
					assertThat(context).hasFailed();
					Throwable cause = NestedExceptionUtils.getMostSpecificCause(context.getStartupFailure());
					assertThat(cause).isInstanceOf(IllegalStateException.class)
							.hasMessageContaining(InMemoryMailer.class.getName());
				});
	}

	@Test
	@DisplayName("운영 프로파일에서 SMTP 발송기가 선택되면 뜬다")
	void 운영에서_SMTP_발송기면_뜬다() {
		this.selection.withPropertyValues("spring.profiles.active=prod")
				.run(context -> assertThat(context).hasNotFailed());
	}

	@Test
	@DisplayName("운영 프로파일이 아니면 시험용 발송기가 선택되어도 뜬다")
	void 운영이_아니면_시험용_발송기로_뜬다() {
		this.selection.withBean(InMemoryMailer.class, InMemoryMailer::new, definition -> definition.setPrimary(true))
				.run(context -> {
					assertThat(context).hasNotFailed();
					assertThat(context.getBean(Mailer.class)).isInstanceOf(InMemoryMailer.class);
				});
	}

	private MailDispatcher dispatcher(Mailer mailer) {
		return new MailDispatcher(mailer, this.handedOver::add, new StandardEnvironment());
	}

	private static ListAppender<ILoggingEvent> attachAppender() {
		ListAppender<ILoggingEvent> appender = new ListAppender<>();
		appender.start();
		((Logger) LoggerFactory.getLogger(MailDispatcher.class)).addAppender(appender);
		return appender;
	}

	private static void detachAppender(ListAppender<ILoggingEvent> appender) {
		((Logger) LoggerFactory.getLogger(MailDispatcher.class)).detachAppender(appender);
		appender.stop();
	}

	/** 자원 없이 Spring 의 트랜잭션 동기화만 돌린다. 커밋·되돌림의 동기화 호출은 상위 클래스가 한다. */
	private static final class NoResourceTransactionManager extends AbstractPlatformTransactionManager {

		@Override
		protected Object doGetTransaction() {
			return new Object();
		}

		@Override
		protected void doBegin(Object transaction, TransactionDefinition definition) {
		}

		@Override
		protected void doCommit(DefaultTransactionStatus status) {
		}

		@Override
		protected void doRollback(DefaultTransactionStatus status) {
		}

	}

}
