package com.example.auth.mail;

/**
 * 메일 발송기. 운영 프로파일이 받는 구현은 {@link SmtpMailer} 다 — {@link MailDispatcher} 가 그 밖의
 * 구현을 운영에서 거부한다 (sp-docs/security.md §12).
 *
 * <p>부르는 쪽은 이것을 직접 쓰지 않고 {@link MailDispatcher#sendAfterCommit} 로 건다. 커밋 뒤에,
 * 요청 스레드 밖에서, 실패를 로그로 남기고 다시 보내지 않는 규칙(sp-docs/requirements/member.md §11.5)이
 * 거기 있다.
 *
 * <p>메일을 메모리에 모으는 시험용 구현은 테스트 소스에만 둔다 (sp-docs/tech-stack.md §4.7).
 */
public interface Mailer {

	/**
	 * 한 통을 보낸다. 실패하면 예외를 던진다 — 다시 보내지 않는 것과 실패의 로그는 {@link MailDispatcher}
	 * 가 맡는다.
	 */
	void send(OutgoingMail mail);

}
