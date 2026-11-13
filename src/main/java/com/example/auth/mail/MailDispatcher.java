package com.example.auth.mail;

import com.example.auth.global.config.MailExecutorConfig;
import java.util.concurrent.Executor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * 메일을 커밋 뒤에, 요청 스레드 밖에서 보낸다 (sp-docs/requirements/member.md §11.5).
 *
 * <ul>
 *   <li><b>커밋 뒤</b> — {@link #sendAfterCommit} 는 지금 트랜잭션이 커밋된 뒤에 발송을 건다. 되돌려지면
 *       보내지 않는다. 트랜잭션 밖에서 부르면 예외를 던진다 — 커밋 뒤를 지킬 수 없는 호출을 바로 보내는
 *       것으로 바꾸지 않는다</li>
 *   <li><b>요청 스레드 밖</b> — 커밋 뒤에 발송을 발송 실행기({@link MailExecutorConfig})로 넘긴다. 대기열이
 *       차면 실행기가 버리고 WARN 을 남긴다</li>
 *   <li><b>다시 보내지 않는다</b> — 실패하면 WARN 한 줄로 끝낸다. 그 줄에는 계정 id·목적·예외의 종류만
 *       싣는다 (sp-docs/security.md §12). 예외의 메시지와 스택은 싣지 않는다 — 그것이 무엇을 담는지는
 *       던진 쪽이 정하므로, 이 규칙 밖의 값이 들어가도 여기서 막을 수 없다</li>
 * </ul>
 *
 * <p><b>운영 프로파일에서는 {@link SmtpMailer} 만 받는다.</b> 메일을 메모리에 모으는 시험용 발송기가
 * 선택된 채 운영 프로파일로 뜨면 기동이 실패한다 (sp-docs/security.md §12, sp-docs/tech-stack.md §4.7).
 * 어느 발송기가 선택됐는지는 이 생성자가 주입받을 때 정해지므로 여기서 본다.
 */
@Component
public class MailDispatcher {

	private static final Logger log = LoggerFactory.getLogger(MailDispatcher.class);

	private final Mailer mailer;

	private final Executor mailExecutor;

	public MailDispatcher(
			Mailer mailer,
			@Qualifier(MailExecutorConfig.MAIL_EXECUTOR) Executor mailExecutor,
			Environment environment) {

		if (environment.acceptsProfiles(Profiles.of(MailConfig.PROD_PROFILE)) && !(mailer instanceof SmtpMailer)) {
			throw new IllegalStateException("운영 프로파일의 메일 발송기가 SMTP 구현이 아니다: "
					+ mailer.getClass().getName() + ". 시험용 발송기는 테스트에서만 쓴다 (sp-docs/security.md §12).");
		}
		this.mailer = mailer;
		this.mailExecutor = mailExecutor;
	}

	/**
	 * 지금 트랜잭션이 커밋된 뒤에 보낸다. 되돌려지면 보내지 않는다.
	 *
	 * @throws IllegalStateException 트랜잭션 동기화가 없을 때 — 아무것도 걸지 않는다
	 */
	public void sendAfterCommit(OutgoingMail mail) {
		if (!TransactionSynchronizationManager.isSynchronizationActive()) {
			throw new IllegalStateException("메일은 커밋 뒤에 보낸다 — 트랜잭션 안에서 건다 "
					+ "(sp-docs/requirements/member.md §11.5).");
		}
		TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
			@Override
			public void afterCommit() {
				MailDispatcher.this.mailExecutor.execute(() -> send(mail));
			}
		});
	}

	private void send(OutgoingMail mail) {
		try {
			this.mailer.send(mail);
		} catch (RuntimeException e) {
			// 예외 객체를 로그 인자로 넘기지 않는다 — 넘기면 메시지와 스택이 함께 남는다
			log.warn("mail send failed: accountId={}, purpose={}, exception={}, cause={}",
					mail.accountId(), mail.purpose(), e.getClass().getName(),
					NestedExceptionUtils.getMostSpecificCause(e).getClass().getName());
		}
	}

}
