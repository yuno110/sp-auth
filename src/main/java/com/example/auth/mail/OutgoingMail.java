package com.example.auth.mail;

/**
 * 보낼 메일 한 통.
 *
 * <p>{@code accountId}·{@code purpose} 는 받는 사람에게 가지 않는다. 발송이 실패했을 때 로그가 남기는
 * 계정 id 와 목적이다 — 로그에는 계정 id·목적·실패의 종류만 남긴다
 * (sp-docs/requirements/member.md §11.5, sp-docs/security.md §12). {@code purpose} 가 문자열인 것은 이
 * 패키지가 {@code account} 를 부르지 않기 때문이다 (sp-docs/conventions.md §1.1) — 부르는 쪽이 목적의
 * 이름을 넣는다.
 *
 * <p>{@link #toString()} 은 받는 주소·제목·본문을 내지 않는다. 본문에는 링크와 그 안의 토큰이 있다 —
 * 이 객체가 로그 인자로 넘어가도 새지 않게 한다.
 *
 * @param accountId 받는 계정의 id
 * @param purpose 목적의 이름(예: 토큰 목적)
 * @param to 받는 주소. 계정에 저장된 주소다 — 요청에 실린 표기가 아니다 (sp-docs/security.md §12)
 * @param subject 제목
 * @param text 본문(평문)
 */
public record OutgoingMail(Long accountId, String purpose, String to, String subject, String text) {

	@Override
	public String toString() {
		return "OutgoingMail[accountId=" + this.accountId + ", purpose=" + this.purpose + "]";
	}

}
