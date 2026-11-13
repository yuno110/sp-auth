package com.example.auth.support;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;

/**
 * 테스트 컨텍스트의 발송기를 {@link InMemoryMailer} 로 고른다. 테스트는 SMTP 에 접속하지 않는다
 * (sp-docs/plan/phase2-auth-member.md AU-14).
 *
 * <p>{@code com.example.auth} 아래의 {@code @Configuration} 이라 {@code @SpringBootTest} 의 컴포넌트
 * 스캔이 집어 간다 — 테스트 클래스마다 가져올 필요가 없다. 운영의 {@code SmtpMailer} 빈도 함께 있으므로
 * {@link Primary} 로 이것이 주입되게 한다. {@code SmtpMailer} 는 만들어져도 보내기 전에는 SMTP 에
 * 접속하지 않는다.
 *
 * <p><b>운영 프로파일을 켠 컨텍스트에는 넣지 않는다.</b> 그 프로파일에서 시험용 발송기가 선택되면
 * 기동이 실패해야 하고(sp-docs/security.md §12), {@code ProdProfileTest} 는 운영의 배선을 그대로 본다.
 * 운영 프로파일에서 이것이 선택된 경우의 실패는 {@code MailDispatcherTest} 가 컨텍스트에 직접 넣어 본다.
 */
@Configuration(proxyBeanMethods = false)
@Profile("!prod")
public class TestMailConfig {

	@Bean
	@Primary
	public InMemoryMailer inMemoryMailer() {
		return new InMemoryMailer();
	}

}
