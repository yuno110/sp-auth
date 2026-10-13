package com.example.auth.global.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.example.auth.account.entity.Role;
import com.example.auth.global.security.JwtTokenProvider;
import com.example.auth.support.TestRsaKeys;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * {@link JwtConfig} 의 {@code JwtDecoder} 가 쓰는 <b>claim 검증기 집합을 고정한다</b>
 * (sp-docs/plan/phase1.md §4 AU-11. AU-07 에서 넘어온 것이다).
 *
 * <p><b>왜 집합을 고정해야 하나</b> — {@link JwtTokenProvider#failureCode} 는 예외 <i>타입</i>만
 * 보고 {@code A002}(유효하지 않음)와 {@code A003}(만료)를 가른다
 * (sp-docs/api-contract.md §8.1 §8.5). {@code NimbusJwtDecoder} 는 서명을 먼저 보고 claim 을
 * 나중에 보므로, 서명을 통과한 뒤의 {@code JwtValidationException} 은 claim 검증 실패 하나뿐이다.
 * 그 claim 검증기가 <b>만료만 보는 것들이기 때문에</b> {@code JwtValidationException} = 만료가
 * 성립한다. 검증기가 하나 늘면 그 등식이 조용히 깨진다 — 예컨대 {@code iss} 검증기를 붙이면
 * <b>발급자 불일치가 "만료된 토큰"으로 나간다.</b>
 *
 * <p><b>이 테스트는 주석이 아니라 단언으로 수량을 말한다.</b> sp-docs/conventions.md §9.5 가
 * 금지하는 것은 주석의 수량 주장이고, 이유는 다음 항목이 늘렸을 때 걸러 줄 기계장치가 없다는
 * 것이다. 여기서는 수량이 곧 검증 대상이고 늘어나면 단언이 깨진다 — 기계장치가 이것이다.
 * <b>깨지는 것이 의도다.</b> 깨졌을 때 할 일은 아래 목록을 늘리는 것이 아니라
 * {@code failureCode} 를 함께 고치는 것이다.
 */
class JwtConfigTest {

	/**
	 * {@code JwtValidators.createDefault()} 가 거는 검증기들. {@code JwtDecoder} 를
	 * {@code NimbusJwtDecoder.withPublicKey(...)} 로 만들면 이것이 기본값이 된다.
	 *
	 * <p><b>클래스 리터럴이 아니라 이름으로 적는다</b> — {@code X509CertificateThumbprintValidator}
	 * 는 Spring Security 안에서 package-private 이라 테스트가 참조할 수 없다.
	 */
	private static final List<String> PINNED_CLAIM_VALIDATORS = List.of(
			"org.springframework.security.oauth2.jwt.JwtTimestampValidator",
			"org.springframework.security.oauth2.jwt.X509CertificateThumbprintValidator");

	@Test
	@DisplayName("JwtDecoder 의 claim 검증기 집합이 만료만 보는 둘로 고정되어 있다")
	void claim_검증기_집합이_고정되어_있다() {
		jwtConfigRunner().run(context -> {
			JwtDecoder decoder = context.getBean(JwtDecoder.class);

			assertThat(decoder)
					.as("검증기 집합을 읽으려면 NimbusJwtDecoder 여야 한다")
					.isInstanceOf(NimbusJwtDecoder.class);

			assertThat(claimValidatorsOf(decoder))
					.as("집합이 바뀌면 JwtTokenProvider.failureCode 의 'JwtValidationException = 만료' "
							+ "전제가 깨진다. 이 목록을 늘리지 말고 failureCode 를 함께 고친다")
					.containsExactlyInAnyOrderElementsOf(PINNED_CLAIM_VALIDATORS);
		});
	}

	/**
	 * 위 집합이 실제로 무엇을 뜻하는지 — <b>발급자 불일치가 claim 검증에 걸리지 않는다.</b>
	 *
	 * <p>{@code iss} 검증기가 붙는 순간 이 테스트가 먼저 깨지므로, 집합 단언과 함께 "무엇이
	 * 왜 깨졌는지"를 보여 준다. 토큰은 서명이 옳고 만료되지 않았으므로 걸릴 것은 {@code iss}
	 * 하나다.
	 */
	@Test
	@DisplayName("iss 가 다른 토큰이 claim 검증에 걸리지 않는다 — 걸리면 failureCode 가 A003 으로 낸다")
	void iss_불일치는_claim_검증에_걸리지_않는다() {
		jwtConfigRunner().run(context -> {
			JwtEncoder encoder = context.getBean(JwtEncoder.class);
			JwtDecoder decoder = context.getBean(JwtDecoder.class);
			String foreignIssuerToken = signWithIssuer(encoder, "not-" + JwtTokenProvider.ISSUER);

			assertThatCode(() -> decoder.decode(foreignIssuerToken))
					.as("여기서 JwtValidationException 이 나면 failureCode 가 그것을 A003(만료)로 낸다. "
							+ "발급자 불일치는 A002 여야 한다 (sp-docs/api-contract.md §8.5)")
					.doesNotThrowAnyException();

			Jwt decoded = decoder.decode(foreignIssuerToken);
			assertThat(decoded.getClaimAsString("iss")).isEqualTo("not-" + JwtTokenProvider.ISSUER);
		});
	}

	/**
	 * {@link JwtConfig} 만 올린 컨텍스트. {@code PropertyPlaceholderAutoConfiguration} 을 함께
	 * 올려 실제 기동과 같은 placeholder 해석 규칙을 쓴다 ({@code JwtTokenProviderTest} 와 같다).
	 */
	private ApplicationContextRunner jwtConfigRunner() {
		return new ApplicationContextRunner()
				.withConfiguration(AutoConfigurations.of(PropertyPlaceholderAutoConfiguration.class))
				.withUserConfiguration(JwtConfig.class)
				.withPropertyValues("jwt.private-key-location=" + TestRsaKeys.privateKeyLocation());
	}

	/**
	 * 디코더가 실제로 거는 claim 검증기들의 클래스 이름.
	 *
	 * <p>{@code jwtValidator} 는 공개 접근자가 없어 리플렉션으로 읽는다. 중첩된
	 * {@code DelegatingOAuth2TokenValidator} 를 펼치는 것은 Spring Security 가 권하는 추가
	 * 방식이 "기본값 + 내 검증기를 새 Delegating 으로 감싸기"이기 때문이다 — 펼치지 않으면
	 * 집합이 늘었는데도 위에서 한 겹만 보인다.
	 */
	private List<String> claimValidatorsOf(JwtDecoder decoder) {
		Object validator = ReflectionTestUtils.getField(decoder, "jwtValidator");
		return flatten(validator).stream().map(each -> each.getClass().getName()).toList();
	}

	@SuppressWarnings("unchecked")
	private List<Object> flatten(Object validator) {
		if (!(validator instanceof DelegatingOAuth2TokenValidator<?>)) {
			return List.of(validator);
		}
		Collection<OAuth2TokenValidator<?>> delegates =
				(Collection<OAuth2TokenValidator<?>>) ReflectionTestUtils.getField(validator, "tokenValidators");
		return delegates.stream().flatMap(each -> flatten(each).stream()).toList();
	}

	/**
	 * {@code iss} 만 바꿔 서명한 토큰. 나머지 claim 은 발급 경로와 같다
	 * (sp-docs/api-contract.md §6).
	 *
	 * <p>{@code TestTokens.signed} 는 {@code iss} 를 계약값으로 못박으므로 쓸 수 없다 — 계약값이
	 * 아닌 발급자가 필요하므로 여기서는 직접 서명한다.
	 */
	private String signWithIssuer(JwtEncoder encoder, String issuer) {
		Instant issuedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS);
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.subject("7")
				.claim(JwtTokenProvider.CLAIM_ROLE, Role.USER.name())
				.issuer(issuer)
				.issuedAt(issuedAt)
				.expiresAt(issuedAt.plus(Duration.ofMinutes(30)))
				.build();
		JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
		return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
	}

}
