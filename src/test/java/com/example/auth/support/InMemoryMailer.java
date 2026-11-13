package com.example.auth.support;

import com.example.auth.mail.Mailer;
import com.example.auth.mail.OutgoingMail;
import java.time.Duration;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * 메일을 메모리에 모으는 시험용 발송기 (sp-docs/tech-stack.md §4.7, sp-docs/security.md §12).
 *
 * <p><b>테스트 소스에만 둔다.</b> 운영 코드에 이 구현이 없고, 운영 프로파일에서 이것이 선택되면
 * {@code MailDispatcher} 가 기동을 실패시킨다. 테스트 컨텍스트에 넣는 것은 {@link TestMailConfig} 다.
 *
 * <p>발송은 실행기 스레드에서 오므로 테스트는 {@link #next(Duration)} 로 기다려 꺼낸다. 보낸 스레드의
 * 이름을 함께 남긴다 — 발송이 요청 스레드 밖에서 도는지 볼 수 있다.
 */
public class InMemoryMailer implements Mailer {

	private final BlockingQueue<Sent> sent = new LinkedBlockingQueue<>();

	@Override
	public void send(OutgoingMail mail) {
		this.sent.add(new Sent(mail, Thread.currentThread().getName()));
	}

	/** 다음 메일을 기다려 꺼낸다. 시간 안에 오지 않으면 실패한다. */
	public Sent next(Duration timeout) throws InterruptedException {
		Sent next = this.sent.poll(timeout.toMillis(), TimeUnit.MILLISECONDS);
		if (next == null) {
			throw new AssertionError(timeout + " 안에 보낸 메일이 없다");
		}
		return next;
	}

	/** 아직 꺼내지 않은 메일을 버린다. 컨텍스트를 함께 쓰는 앞 테스트의 메일이 섞이지 않게 한다. */
	public void clear() {
		this.sent.clear();
	}

	/**
	 * 보낸 메일 한 통과 보낸 스레드의 이름.
	 *
	 * @param mail 보낸 메일
	 * @param threadName {@link Mailer#send} 를 부른 스레드의 이름
	 */
	public record Sent(OutgoingMail mail, String threadName) {
	}

}
