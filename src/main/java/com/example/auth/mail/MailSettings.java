package com.example.auth.mail;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * {@code mail.from}·{@code mail.frontend-base-url} (sp-docs/tech-stack.md §4.7). 둘 다 기본값이 없는
 * 정책값이다.
 *
 * <p>값의 검사는 여기서 하지 않는다 — 애플리케이션이 뜰 때 {@link MailStartupGuard} 가 컨텍스트를 만들기
 * 전에 환경의 원시 값을 보므로, 바인딩되는 값은 그 검사를 지난 것이다. 발송 대기열의
 * 상한({@code mail.executor.queue-capacity})은 실행기 설정이 읽는다.
 *
 * @param from 보내는 주소
 * @param frontendBaseUrl 메일 링크의 기준 주소(화면의 오리진). 요청의 {@code Host}·{@code Origin} 으로
 *     대신하지 않는다 (sp-docs/security.md §12)
 */
@ConfigurationProperties("mail")
public record MailSettings(String from, String frontendBaseUrl) {
}
