package com.example.auth.global.config;

import java.util.Objects;

/**
 * 메일 실행기에 넘기는 작업 하나 — 발급 작업 또는 발송 작업 (sp-docs/requirements/member.md §11.5,
 * sp-docs/security.md §12).
 *
 * <p>대기열이 작업을 버리면 거부 처리기({@link MailExecutorConfig})가 이 형에서 <b>종류·계정 id·목적만</b> 꺼내 WARN 에
 * 적는다. 그래서 이 형은 그 셋 말고는 꺼낼 길을 주지 않는다 — 할 일({@link Runnable})은 이메일·토큰·링크가 담긴 메일을
 * 붙잡고 있을 수 있으므로 감춰 두고 {@link #run()} 으로만 돌린다. {@link #toString()} 도 그 셋만 낸다. record 로 두지
 * 않는다 — 구성 요소마다 접근자가 생기고 기본 {@code toString} 이 할 일까지 낸다.
 *
 * <p>목적은 {@code OutgoingMail} 처럼 이름(문자열)으로 싣는다. 이 형은 {@code global/config} 에 있고 {@code account}·
 * {@code mail} 을 부르지 않는다 — 두 패키지가 이것을 부른다 (sp-docs/conventions.md §1.1).
 */
public final class MailExecutorTask implements Runnable {

	/** 작업의 종류. */
	public enum Kind {
		/** 발급 작업 — 계정 찾기·보낼 조건·발송 상한·새 토큰 넣기. 발급 실행기에서 돈다. */
		ISSUE,
		/** 발송 작업 — SMTP 에 넘기기. 발송 실행기에서 돈다. */
		SEND
	}

	private final Kind kind;

	private final Long accountId;

	private final String purpose;

	private final Runnable work;

	private MailExecutorTask(Kind kind, Long accountId, String purpose, Runnable work) {
		this.kind = Objects.requireNonNull(kind, "kind");
		this.accountId = accountId;
		this.purpose = Objects.requireNonNull(purpose, "purpose");
		this.work = Objects.requireNonNull(work, "work");
	}

	/**
	 * 발급 작업. 재발송·재설정의 발급은 넣는 순간 계정을 모르므로 {@code accountId} 가 {@code null} 이다 — 이메일을 대신
	 * 싣지 않는다 (sp-docs/requirements/member.md §11.5).
	 */
	public static MailExecutorTask issue(Long accountId, String purpose, Runnable work) {
		return new MailExecutorTask(Kind.ISSUE, accountId, purpose, work);
	}

	/** 발송 작업. */
	public static MailExecutorTask send(Long accountId, String purpose, Runnable work) {
		return new MailExecutorTask(Kind.SEND, accountId, purpose, work);
	}

	public Kind kind() {
		return this.kind;
	}

	/** 계정 id. 모르면 {@code null} 이다. */
	public Long accountId() {
		return this.accountId;
	}

	public String purpose() {
		return this.purpose;
	}

	@Override
	public void run() {
		this.work.run();
	}

	/** 종류·계정 id·목적만 낸다. 할 일을 내지 않는다 — 할 일은 이메일과 본문의 링크를 붙잡고 있을 수 있다. */
	@Override
	public String toString() {
		return "MailExecutorTask[kind=" + this.kind + ", accountId=" + this.accountId + ", purpose=" + this.purpose
				+ "]";
	}

}
