package com.example.auth.mail;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.global.config.MailExecutorConfig;
import com.example.auth.support.InMemoryMailer;
import com.example.auth.support.TestRsaKeys;
import java.time.Duration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 애플리케이션 컨텍스트에서의 메일 배선 (sp-docs/plan/phase2-auth-member.md AU-14).
 *
 * <p>테스트 프로파일로 뜬다 — 시험용 발송기가 선택되고 SMTP 에 접속하지 않는다. 트랜잭션은 앱의 관리자로,
 * 실행기는 앱의 발송 실행기로 돈다.
 */
@SpringBootTest
class MailContextTest {

	/** 개인키는 저장소 밖에 있다. 테스트가 실행 시점에 만든 키 페어를 쓴다. */
	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	@Autowired
	private MailDispatcher mailDispatcher;

	@Autowired
	private InMemoryMailer inMemoryMailer;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@Autowired
	private JavaMailSenderImpl javaMailSender;

	@Test
	@DisplayName("커밋 뒤 발송이 발송 실행기의 스레드에서 시험용 발송기로 간다 — 요청 스레드 밖, SMTP 밖이다")
	void 커밋_뒤_발송은_실행기_스레드에서_시험용_발송기로_간다() throws InterruptedException {
		this.inMemoryMailer.clear();
		OutgoingMail mail = new OutgoingMail(7L, "EMAIL_VERIFICATION", "member@example.com", "제목", "본문");

		new TransactionTemplate(this.transactionManager)
				.executeWithoutResult(status -> this.mailDispatcher.sendAfterCommit(mail));

		InMemoryMailer.Sent sent = this.inMemoryMailer.next(Duration.ofSeconds(5));
		assertThat(sent.mail()).isEqualTo(mail);
		assertThat(sent.threadName())
				.startsWith(MailExecutorConfig.THREAD_NAME_PREFIX)
				.isNotEqualTo(Thread.currentThread().getName());
	}

	/**
	 * JavaMail 의 기본은 무한 대기다 (sp-docs/tech-stack.md §4.7). 설정 파일이 아니라 JavaMail 에 실제로
	 * 넘어가는 속성을 본다.
	 */
	@Test
	@DisplayName("SMTP 타임아웃이 연결 5초·읽기 10초·쓰기 10초다")
	void SMTP_타임아웃이_정본의_값이다() {
		assertThat(this.javaMailSender.getJavaMailProperties())
				.containsEntry("mail.smtp.connectiontimeout", "5000")
				.containsEntry("mail.smtp.timeout", "10000")
				.containsEntry("mail.smtp.writetimeout", "10000");
	}

}
