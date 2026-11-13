package com.example.auth.mail;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.mail.MailSenderAutoConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

/**
 * 메일 설정의 기동 가드 ({@link MailStartupGuard}, sp-docs/tech-stack.md §4.7,
 * sp-docs/plan/phase2-auth-member.md AU-14).
 *
 * <p>자리마다의 판정은 가드를 환경 하나에 직접 돌려 본다. 그 환경에서 이 키들을 읽는 것은 가드뿐이라, 가드의
 * 검사 하나를 지우면 그 자리의 테스트가 깨진다. 실제 기동에 들어가 Boot 의 메일 자동 설정보다 먼저 막는지는
 * 맨 아래의 기동 테스트가 본다.
 */
class MailStartupGuardTest {

	/** 어느 환경에도 없을 이름. 해석되지 않아 리터럴 {@code "${…}"} 가 그대로 남는다. */
	private static final String UNRESOLVED = "${MAIL_GUARD_TEST_NOT_SET}";

	/** 시험용 비밀번호. 실패 메시지에 실리지 않아야 한다. */
	private static final String PASSWORD_VALUE = "guard-test-password";

	@Test
	@DisplayName("username·password 가 둘 다 빈 값이고 운영 프로파일이 아니면 뜬다 — 로컬 Mailpit 의 모양")
	void 로컬_Mailpit_의_모양이면_지난다() {
		assertThatCode(() -> guard(mailpitShape())).doesNotThrowAnyException();
	}

	static Stream<Arguments> 정책값의_빈_값과_리터럴() {
		return Stream.of(MailStartupGuard.HOST, MailStartupGuard.PORT, MailStartupGuard.FROM,
						MailStartupGuard.FRONTEND_BASE_URL)
				.flatMap(key -> Stream.of(Arguments.of(key, ""), Arguments.of(key, UNRESOLVED)));
	}

	@ParameterizedTest(name = "{0}=\"{1}\"")
	@MethodSource("정책값의_빈_값과_리터럴")
	@DisplayName("정책값이 비었거나 미해석 리터럴이면 실패하고 메시지가 그 키를 말한다")
	void 정책값이_비었거나_리터럴이면_실패한다(String key, String value) {
		Map<String, Object> values = mailpitShape();
		values.put(key, value);

		String message = guardFailure(values);

		assertThat(message).contains(key);
		if (!value.isEmpty()) {
			assertThat(message)
					.as("리터럴이 가드까지 그대로 왔다 — 읽는 쪽이 해석하다 던진 것이 아니다")
					.contains(value);
		}
	}

	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {"localhost:3000", "/verify-email", "ftp://localhost:3000", "http:localhost",
			"http://", "http:///verify-email"})
	@DisplayName("기준 주소가 http·https 의 절대 URL 이 아니면 실패한다")
	void 기준_주소가_http_https_의_절대_URL_이_아니면_실패한다(String value) {
		Map<String, Object> values = mailpitShape();
		values.put(MailStartupGuard.FRONTEND_BASE_URL, value);

		assertThat(guardFailure(values)).contains(MailStartupGuard.FRONTEND_BASE_URL, "http·https");
	}

	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {"http://localhost:3000", "https://sp.example.com"})
	@DisplayName("기준 주소는 http 와 https 를 둘 다 받는다")
	void 기준_주소는_http_와_https_를_받는다(String value) {
		Map<String, Object> values = mailpitShape();
		values.put(MailStartupGuard.FRONTEND_BASE_URL, value);

		assertThatCode(() -> guard(values)).doesNotThrowAnyException();
	}

	static Stream<Arguments> 하나만_있는_계정() {
		return Stream.of(
				Arguments.of("local", "smtp-user", ""),
				Arguments.of("local", "", PASSWORD_VALUE),
				Arguments.of(MailConfig.PROD_PROFILE, "smtp-user", ""),
				Arguments.of(MailConfig.PROD_PROFILE, "", PASSWORD_VALUE));
	}

	@ParameterizedTest(name = "{0}: username=\"{1}\"")
	@MethodSource("하나만_있는_계정")
	@DisplayName("username·password 중 하나만 있으면 어느 프로파일이든 실패한다")
	void 계정이_하나만_있으면_실패한다(String profile, String username, String password) {
		assertThat(guardFailure(withAccount(username, password), profile))
				.contains(MailStartupGuard.USERNAME, MailStartupGuard.PASSWORD, "하나만")
				.doesNotContain(PASSWORD_VALUE);
	}

	@Test
	@DisplayName("운영 프로파일은 username·password 가 둘 다 빈 값이면 실패한다")
	void 운영에서_계정이_없으면_실패한다() {
		assertThat(guardFailure(withAccount("", ""), MailConfig.PROD_PROFILE))
				.contains("운영 프로파일", MailStartupGuard.USERNAME, MailStartupGuard.PASSWORD);
	}

	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {"local", MailConfig.PROD_PROFILE})
	@DisplayName("username·password 가 둘 다 있으면 운영이든 아니든 지난다")
	void 계정이_둘_다_있으면_지난다(String profile) {
		assertThatCode(() -> guard(withAccount("smtp-user", PASSWORD_VALUE), profile))
				.doesNotThrowAnyException();
	}

	static Stream<Arguments> 리터럴_계정() {
		return Stream.of(
				Arguments.of("local", UNRESOLVED, UNRESOLVED, MailStartupGuard.USERNAME),
				Arguments.of("local", "smtp-user", UNRESOLVED, MailStartupGuard.PASSWORD),
				Arguments.of(MailConfig.PROD_PROFILE, UNRESOLVED, UNRESOLVED, MailStartupGuard.USERNAME),
				Arguments.of(MailConfig.PROD_PROFILE, "smtp-user", UNRESOLVED, MailStartupGuard.PASSWORD));
	}

	/**
	 * 운영이 아니어도 막는다. 둘 다 리터럴이면 「하나만 있다」 에 걸리지 않는데, 그대로 두면 리터럴이 SMTP
	 * 접속의 자격 증명으로 넘어간다 ({@link MailStartupGuard} 의 계정 검사 주석).
	 */
	@ParameterizedTest(name = "{0}: {3}")
	@MethodSource("리터럴_계정")
	@DisplayName("username·password 가 미해석 리터럴이면 어느 프로파일이든 실패하고 값을 싣지 않는다")
	void 계정이_리터럴이면_실패한다(String profile, String username, String password, String failingKey) {
		assertThat(guardFailure(withAccount(username, password), profile))
				.contains(failingKey, "해석되지 않은")
				.doesNotContain(UNRESOLVED);
	}

	// --- 실제 기동 ---

	/**
	 * {@code META-INF/spring.factories} 로 기동에 들어가고, 컨텍스트를 만들기 전에 막는지 본다.
	 *
	 * <p>Boot 의 메일 자동 설정을 함께 올린다. 그 조건 평가는 {@code spring.mail.host} 를 해석하다 미해석
	 * placeholder 에서 스스로 실패하고, 그 바인딩은 {@code port} 를 정수로 바꾼다 — 가드가 그보다 늦으면 실패의
	 * 출처가 그쪽이 되어 메시지가 가드의 것이 아니다. 나머지 값은 테스트 프로파일의 설정 파일이 채운다.
	 */
	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {MailStartupGuard.HOST, MailStartupGuard.PORT})
	@DisplayName("실제 기동에서 가드가 Boot 의 메일 자동 설정보다 먼저 미해석 리터럴을 막는다")
	void 실제_기동에서_가드가_메일_자동_설정보다_먼저_막는다(String key) {
		SpringApplication application = new SpringApplication(MailAutoConfigurationOnly.class);
		application.setWebApplicationType(WebApplicationType.NONE);

		Throwable failure = catchThrowable(
				() -> application.run("--spring.profiles.active=test", "--" + key + "=" + UNRESOLVED).close());

		assertThat(failure)
				.as("가드의 실패다 — 다른 쪽이 먼저 실패하면 예외가 감싸이거나 메시지가 가드의 것이 아니다")
				.isInstanceOf(IllegalStateException.class)
				.hasNoCause()
				.hasMessageContaining(key)
				.hasMessageContaining("해석되지 않은 placeholder " + UNRESOLVED);
	}

	@Configuration(proxyBeanMethods = false)
	@ImportAutoConfiguration(MailSenderAutoConfiguration.class)
	static class MailAutoConfigurationOnly {
	}

	// --- 도우미 ---

	/** 로컬 Mailpit 의 모양 — 운영이 아니고 username·password 가 둘 다 빈 값이다 (§4.7.1). */
	private static Map<String, Object> mailpitShape() {
		Map<String, Object> values = new LinkedHashMap<>();
		values.put(MailStartupGuard.HOST, "localhost");
		values.put(MailStartupGuard.PORT, "1025");
		values.put(MailStartupGuard.USERNAME, "");
		values.put(MailStartupGuard.PASSWORD, "");
		values.put(MailStartupGuard.FROM, "no-reply@localhost");
		values.put(MailStartupGuard.FRONTEND_BASE_URL, "http://localhost:3000");
		return values;
	}

	private static Map<String, Object> withAccount(String username, String password) {
		Map<String, Object> values = mailpitShape();
		values.put(MailStartupGuard.USERNAME, username);
		values.put(MailStartupGuard.PASSWORD, password);
		return values;
	}

	/** 값과 프로파일로 환경을 만들어 가드를 돌린다. 값은 맨 앞의 속성 소스라 다른 소스가 덮지 않는다. */
	private static void guard(Map<String, Object> values, String... profiles) {
		StandardEnvironment environment = new StandardEnvironment();
		environment.getPropertySources().addFirst(new MapPropertySource("mail-guard-test", values));
		environment.setActiveProfiles(profiles);
		new MailStartupGuard().postProcessEnvironment(environment, new SpringApplication());
	}

	/** 가드가 {@link IllegalStateException} 으로 실패했음을 확인하고 그 메시지를 돌려준다. */
	private static String guardFailure(Map<String, Object> values, String... profiles) {
		Throwable failure = catchThrowable(() -> guard(values, profiles));
		assertThat(failure)
				.as("가드의 실패여야 한다 — 다른 원인의 기동 실패와 가르려고 메시지가 키를 말한다")
				.isInstanceOf(IllegalStateException.class);
		return failure.getMessage();
	}

}
