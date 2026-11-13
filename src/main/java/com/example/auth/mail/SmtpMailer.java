package com.example.auth.mail;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

/**
 * SMTP 로 보내는 발송기.
 *
 * <p>접속·타임아웃·암호화 연결은 {@code spring.mail.*} 가 정한다 (sp-docs/tech-stack.md §4.7) — Boot 가 그
 * 설정으로 만든 {@link JavaMailSender} 를 쓴다. 보내는 주소는 {@code mail.from} 이다.
 */
@Component
public class SmtpMailer implements Mailer {

	private final JavaMailSender javaMailSender;

	private final MailSettings settings;

	public SmtpMailer(JavaMailSender javaMailSender, MailSettings settings) {
		this.javaMailSender = javaMailSender;
		this.settings = settings;
	}

	@Override
	public void send(OutgoingMail mail) {
		SimpleMailMessage message = new SimpleMailMessage();
		message.setFrom(this.settings.from());
		message.setTo(mail.to());
		message.setSubject(mail.subject());
		message.setText(mail.text());
		this.javaMailSender.send(message);
	}

}
