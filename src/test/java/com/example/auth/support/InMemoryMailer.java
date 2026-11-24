package com.example.auth.support;

import com.example.auth.mail.Mailer;
import com.example.auth.mail.OutgoingMail;
import java.time.Duration;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.springframework.mail.MailSendException;

/**
 * 메일을 메모리에 모으는 시험용 발송기 (sp-docs/tech-stack.md §4.7, sp-docs/security.md §12).
 *
 * <p><b>테스트 소스에만 둔다.</b> 운영 코드에 이 구현이 없고, 운영 프로파일에서 이것이 선택되면
 * {@code MailDispatcher} 가 기동을 실패시킨다. 테스트 컨텍스트에 넣는 것은 {@link TestMailConfig} 다.
 *
 * <p>발송은 실행기 스레드에서 오므로 테스트는 {@link #next(Duration)} 로 기다려 꺼낸다. 보낸 스레드의
 * 이름을 함께 남긴다 — 발송이 요청 스레드 밖에서 도는지 볼 수 있다.
 *
 * <p>{@link #hold()} 는 다음 발송을 풀 때까지 붙잡는다 — SMTP 가 응답하지 않아 발송 스레드가 묶인 상황이다.
 * {@link #failing()} 은 발송이 던지게 한다 — SMTP 가 메일을 받지 않은 상황이다.
 */
public class InMemoryMailer implements Mailer {

	/** 붙잡힌 발송이 기다리는 가장 긴 시간. 테스트가 풀지 않고 끝나도 실행기 스레드가 영영 묶이지 않는다. */
	private static final long HOLD_TIMEOUT_SECONDS = 30;

	private final BlockingQueue<Sent> sent = new LinkedBlockingQueue<>();

	private volatile Hold hold;

	private volatile boolean failing;

	@Override
	public void send(OutgoingMail mail) {
		if (this.failing) {
			throw new MailSendException("시험용 발송기가 실패한다");
		}
		Hold current = this.hold;
		if (current != null) {
			current.entered.countDown();
			try {
				current.released.await(HOLD_TIMEOUT_SECONDS, TimeUnit.SECONDS);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
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
	 * 지금부터 들어오는 발송을 {@link Hold#close()} 까지 붙잡는다. 붙잡힌 발송은 풀린 뒤에 보낸 것으로 남는다.
	 * 테스트는 {@code try}-with-resources 로 연다 — 풀지 않고 끝나면 다음 테스트의 발송이 묶인다.
	 */
	public Hold hold() {
		Hold next = new Hold();
		this.hold = next;
		return next;
	}

	/**
	 * 닫을 때까지 발송이 던진다 — SMTP 가 연결을 거부하거나 받지 않는 상황이다. 던진 메일은 보낸 것으로 남지 않는다.
	 * 테스트는 {@code try}-with-resources 로 연다.
	 */
	public Failing failing() {
		this.failing = true;
		return () -> this.failing = false;
	}

	/**
	 * 보낸 메일 한 통과 보낸 스레드의 이름.
	 *
	 * @param mail 보낸 메일
	 * @param threadName {@link Mailer#send} 를 부른 스레드의 이름
	 */
	public record Sent(OutgoingMail mail, String threadName) {
	}

	/** 실패시키기 하나. 닫으면 다시 보낸다. */
	public interface Failing extends AutoCloseable {

		@Override
		void close();

	}

	/** 붙잡기 하나. 닫으면 붙잡힌 발송이 풀리고 그 뒤의 발송은 붙잡히지 않는다. */
	public final class Hold implements AutoCloseable {

		private final CountDownLatch entered = new CountDownLatch(1);

		private final CountDownLatch released = new CountDownLatch(1);

		private Hold() {
		}

		/** 발송 하나가 붙잡힐 때까지 기다린다. */
		public boolean awaitHeld(Duration timeout) throws InterruptedException {
			return this.entered.await(timeout.toMillis(), TimeUnit.MILLISECONDS);
		}

		@Override
		public void close() {
			if (InMemoryMailer.this.hold == this) {
				InMemoryMailer.this.hold = null;
			}
			this.released.countDown();
		}

	}

}
