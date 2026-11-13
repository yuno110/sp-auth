package com.example.auth.mail;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

/**
 * SMTP 발송기가 메일을 옮겨 담는 것 ({@link SmtpMailer}). 보내는 주소는 설정에서, 받는 주소·제목·본문은
 * 부르는 쪽의 메일에서 온다.
 */
class SmtpMailerTest {

	@Test
	@DisplayName("보내는 주소는 mail.from 이고 받는 주소·제목·본문은 메일의 것이다")
	void 보내는_주소는_설정이고_나머지는_메일의_것이다() {
		JavaMailSender javaMailSender = mock(JavaMailSender.class);
		SmtpMailer mailer = new SmtpMailer(javaMailSender,
				new MailSettings("no-reply@localhost", "http://localhost:3000"));

		mailer.send(new OutgoingMail(7L, "EMAIL_VERIFICATION", "member@example.com", "제목", "본문"));

		ArgumentCaptor<SimpleMailMessage> captor = ArgumentCaptor.forClass(SimpleMailMessage.class);
		verify(javaMailSender).send(captor.capture());
		SimpleMailMessage sent = captor.getValue();
		assertThat(sent.getFrom()).isEqualTo("no-reply@localhost");
		assertThat(sent.getTo()).containsExactly("member@example.com");
		assertThat(sent.getSubject()).isEqualTo("제목");
		assertThat(sent.getText()).isEqualTo("본문");
	}

}
