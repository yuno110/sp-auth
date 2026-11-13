package com.example.auth.mail;

import java.net.URI;
import java.net.URISyntaxException;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Profiles;
import org.springframework.util.StringUtils;

/**
 * 메일 설정의 기동 가드 (sp-docs/tech-stack.md §4.7).
 *
 * <p><b>값을 읽는 쪽의 동작에 기대지 않는다.</b> {@code @ConfigurationProperties} 는 해석되지 않은
 * placeholder 를 리터럴 {@code "${…}"} 로 통과시키고, 빈 환경변수는 빈 문자열로 해석된다
 * (sp-docs/tech-stack.md §4.3 의 측정). 기본값을 두지 않는 것이 기동 실패를 보장하지 않으므로 — 실패하느냐는
 * 그 값을 받는 쪽에 달렸다(같은 절) — 키마다 비었는지와 리터럴인지를 여기서 본다. {@code FlywayConfig} 의
 * ADMIN seed 해시 검사와 같은 방식이다.
 *
 * <p><b>환경 후처리기로 둔 이유는 순서다.</b> 설정 파일을 읽은 뒤, 컨텍스트를 만들기 전에 돈다 — 이 키들을
 * 읽는 다른 쪽보다 앞선다. 빈 팩토리 후처리기로는 늦었다: 2026-11-13 AU-14 가 그렇게 두고 메일 설정 없이
 * {@code local} 로 띄우자, Boot 의 메일 자동 설정({@code MailSenderAutoConfiguration})의 조건 평가가
 * {@code ${MAIL_HOST}} 를 해석하다 {@code PlaceholderResolutionException} 으로 먼저 실패했다. 판정이 그런
 * 읽기의 결과에 달리지 않게 한다. 등록은 {@code META-INF/spring.factories} 다.
 *
 * <p>실패 메시지는 어느 키인지 말한다 — 다른 원인의 기동 실패와 가르려는 것이다
 * (sp-docs/plan/phase2-auth-member.md AU-14 의 검증). 비밀값({@code username}·{@code password})은 값을
 * 메시지에 싣지 않는다 (sp-docs/conventions.md §8).
 *
 * <p>시험용 발송기가 선택된 채 운영으로 뜨는 것은 여기서 보지 않는다. 어느 발송기가 선택됐는지는 빈이
 * 만들어진 뒤에 알 수 있어 {@link MailDispatcher} 가 본다.
 */
public class MailStartupGuard implements EnvironmentPostProcessor {

	static final String HOST = "spring.mail.host";

	static final String PORT = "spring.mail.port";

	static final String USERNAME = "spring.mail.username";

	static final String PASSWORD = "spring.mail.password";

	static final String FROM = "mail.from";

	static final String FRONTEND_BASE_URL = "mail.frontend-base-url";

	@Override
	public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
		Binder binder = Binder.get(environment);

		// 정책값. 비었거나 리터럴이면 실패한다 (sp-docs/tech-stack.md §4.7 의 표)
		requireValue(binder, HOST);
		requireValue(binder, PORT);
		// mail.from 은 「정책값마다 기동 시점의 검사를 두고 그 실패를 테스트가 본다」 가 근거다 (같은 §4.7)
		requireValue(binder, FROM);
		// 기준 주소는 http·https 의 절대 URL 이어야 한다 (sp-docs/tech-stack.md §4.7 의 표)
		requireHttpUrl(binder, FRONTEND_BASE_URL);

		checkCredentials(binder, environment.acceptsProfiles(Profiles.of(MailConfig.PROD_PROFILE)));
	}

	/**
	 * {@code username}·{@code password} 는 비밀값이라 {@code application.yml} 에 기본값이 없다
	 * (sp-docs/tech-stack.md §4.7 의 표).
	 *
	 * <ul>
	 *   <li>해석되지 않은 리터럴은 어느 프로파일에서도 받지 않는다. {@code JavaMailSenderImpl#connectTransport}
	 *       는 사용자 이름이 빈 문자열일 때만 {@code null} 로 바꾸고 그 밖의 문자열은 {@code Transport.connect}
	 *       에 자격 증명으로 그대로 넘긴다(2026-11-13 AU-14 가 바이트코드로 읽었다) — 리터럴이 자격 증명이
	 *       된다</li>
	 *   <li>하나만 있으면 어느 프로파일이든 실패한다 — 같은 표</li>
	 *   <li>운영 프로파일은 둘 다 있어야 한다 — 같은 표. 그 밖의 프로파일은 둘 다 빈 값이어도 뜬다. 로컬의
	 *       Mailpit 은 인증을 받지 않는다 (sp-docs/tech-stack.md §4.7.1)</li>
	 * </ul>
	 */
	private static void checkCredentials(Binder binder, boolean prod) {
		String username = read(binder, USERNAME);
		String password = read(binder, PASSWORD);

		rejectUnresolvedSecret(USERNAME, username);
		rejectUnresolvedSecret(PASSWORD, password);

		boolean hasUsername = StringUtils.hasText(username);
		boolean hasPassword = StringUtils.hasText(password);
		if (hasUsername != hasPassword) {
			throw new IllegalStateException(USERNAME + "·" + PASSWORD + " 중 하나만 있다. 둘 다 주거나 둘 다 "
					+ "비운다 — 로컬의 Mailpit 은 둘 다 빈 값이다 (sp-docs/tech-stack.md §4.7 §4.7.1).");
		}
		if (prod && !hasUsername) {
			throw new IllegalStateException("운영 프로파일은 " + USERNAME + "·" + PASSWORD + " 가 둘 다 있어야 "
					+ "한다. 환경변수 MAIL_USERNAME·MAIL_PASSWORD 로 준다 (sp-docs/tech-stack.md §4.7).");
		}
	}

	private static void rejectUnresolvedSecret(String key, String value) {
		if (value != null && isUnresolved(value)) {
			// 리터럴은 비밀이 아니지만 이 키의 값은 싣지 않는다 — 비밀번호가 "${" 로 시작할 수도 있다
			throw new IllegalStateException(key + " 의 값이 해석되지 않은 placeholder 다. 그 환경변수가 없다. "
					+ "인증이 없는 SMTP 면 빈 값으로 준다 (sp-docs/tech-stack.md §4.3 §4.7).");
		}
	}

	private static String requireValue(Binder binder, String key) {
		String value = read(binder, key);
		if (!StringUtils.hasText(value)) {
			throw new IllegalStateException(key + " 의 값이 없다. 기본값을 두지 않는 설정이다 — 배포는 "
					+ "환경변수로, 로컬은 application-local.yml 로 준다 (sp-docs/tech-stack.md §4.7).");
		}
		if (isUnresolved(value)) {
			throw new IllegalStateException(key + " 의 값이 해석되지 않은 placeholder " + value + " 다. 그 "
					+ "환경변수가 없다 (sp-docs/tech-stack.md §4.3 §4.7).");
		}
		return value;
	}

	/**
	 * 링크의 기준 주소다. 스킴이 {@code http}·{@code https} 이고 호스트가 있어야 한다 — {@code http:foo}
	 * 처럼 스킴만 있는 값도 절대 URI 이지만 그 뒤에 경로를 붙여 링크를 만들 수 없다.
	 */
	private static void requireHttpUrl(Binder binder, String key) {
		String value = requireValue(binder, key);
		if (!isAbsoluteHttpUrl(value)) {
			throw new IllegalStateException(key + " 의 값이 http·https 의 절대 URL 이 아니다: " + value
					+ " — 메일 링크의 기준 주소다 (sp-docs/tech-stack.md §4.7).");
		}
	}

	private static boolean isAbsoluteHttpUrl(String value) {
		try {
			URI uri = new URI(value);
			String scheme = uri.getScheme();
			return ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)) && uri.getHost() != null;
		} catch (URISyntaxException e) {
			return false;
		}
	}

	/**
	 * 환경의 원시 값. 해석되지 않은 placeholder 는 리터럴 그대로 온다 — {@code @ConfigurationProperties}
	 * 와 같은 {@link Binder} 로 읽기 때문이다.
	 */
	private static String read(Binder binder, String key) {
		return binder.bind(key, String.class).orElse(null);
	}

	private static boolean isUnresolved(String value) {
		return value.startsWith("${");
	}

}
