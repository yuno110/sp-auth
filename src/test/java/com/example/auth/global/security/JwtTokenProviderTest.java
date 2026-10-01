package com.example.auth.global.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.account.entity.Role;
import com.example.auth.auth.dto.TokenResponse;
import com.example.auth.global.config.JwtConfig;
import com.example.auth.support.TestRsaKeys;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * sp-docs/plan/phase1.md §4 AU-04 의 "검증" 표 중 토큰 쪽을 테스트로 옮긴 것이다.
 *
 * <p>Claim 계약의 정본은 sp-docs/api-contract.md §6 이고 <b>세 서비스가 공유한다.</b> 그래서
 * claim 집합을 "있는지"가 아니라 <b>"정확히 이 다섯 개인지"</b>로 단언한다 — claim 이 하나
 * 늘어나는 것도 계약 위반이다.
 *
 * <p>서명 검증은 {@link TestRsaKeys#publicKey()} 로 만든 디코더로 한다. member·board 가 공개키
 * 하나만 들고 검증하는 상황과 같게 보기 위해서다 (sp-docs/security.md §2).
 */
@SpringBootTest
@ActiveProfiles("test")
class JwtTokenProviderTest {

	/** sp-docs/security.md §1: Access 30분. */
	private static final long ACCESS_TOKEN_SECONDS = 1800L;

	/** sp-docs/security.md §1: Refresh 14일. */
	private static final long REFRESH_TOKEN_SECONDS = 1_209_600L;

	/** sp-docs/api-contract.md §6 의 claim 전체. 하나라도 늘거나 줄면 계약이 깨진다. */
	private static final String[] CONTRACT_CLAIMS = {"sub", "role", "iss", "iat", "exp"};

	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	@Test
	@DisplayName("Access Token 을 디코딩하면 sub·role·iss 가 발급 값과 일치한다")
	void access_token_의_claim() throws Exception {
		TokenResponse response = this.jwtTokenProvider.issue(7L, Role.ADMIN);

		SignedJWT jwt = SignedJWT.parse(response.accessToken());

		assertThat(jwt.getJWTClaimsSet().getSubject())
				.as("sub 은 account.id 의 문자열이다 (sp-docs/api-contract.md §6)")
				.isEqualTo("7");
		assertThat(jwt.getJWTClaimsSet().getStringClaim("role")).isEqualTo("ADMIN");
		assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo("auth-service");
	}

	@Test
	@DisplayName("디코딩한 Claim 집합에 nickname 키가 없다")
	void nickname_claim_이_없다() throws Exception {
		TokenResponse response = this.jwtTokenProvider.issue(7L, Role.USER);

		Map<String, Object> accessClaims = SignedJWT.parse(response.accessToken())
				.getJWTClaimsSet().getClaims();
		Map<String, Object> refreshClaims = SignedJWT.parse(response.refreshToken())
				.getJWTClaimsSet().getClaims();

		assertThat(accessClaims)
				.as("auth 는 닉네임을 소유하지 않는다. 넣으면 소유하지 않은 값을 서명하는 것이다 "
						+ "(sp-docs/api-contract.md §6)")
				.doesNotContainKey("nickname")
				.containsOnlyKeys(CONTRACT_CLAIMS);
		assertThat(refreshClaims)
				.doesNotContainKey("nickname")
				.containsOnlyKeys(CONTRACT_CLAIMS);
	}

	@Test
	@DisplayName("토큰 header 의 alg 가 RS256 이고 kid 가 있다")
	void header_는_RS256_과_kid_를_갖는다() throws Exception {
		TokenResponse response = this.jwtTokenProvider.issue(7L, Role.USER);

		SignedJWT accessToken = SignedJWT.parse(response.accessToken());
		SignedJWT refreshToken = SignedJWT.parse(response.refreshToken());

		assertThat(accessToken.getHeader().getAlgorithm().getName())
				.as("HS256 을 쓰지 않는다 (sp-docs/adr/0004)")
				.isEqualTo("RS256");
		assertThat(accessToken.getHeader().getKeyID())
				.as("키 회전을 위해 header 에 kid 를 포함한다 (sp-docs/security.md §3)")
				.isNotBlank();
		assertThat(refreshToken.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
		assertThat(refreshToken.getHeader().getKeyID()).isNotBlank();
	}

	@Test
	@DisplayName("Access Token 의 exp - iat 가 1800초, Refresh Token 이 1209600초다")
	void 만료_시간() throws Exception {
		TokenResponse response = this.jwtTokenProvider.issue(7L, Role.USER);

		assertThat(validitySeconds(response.accessToken())).isEqualTo(ACCESS_TOKEN_SECONDS);
		assertThat(validitySeconds(response.refreshToken())).isEqualTo(REFRESH_TOKEN_SECONDS);
		assertThat(response.accessTokenExpiresIn())
				.as("응답의 accessTokenExpiresIn 은 초 단위다 (sp-docs/api-contract.md §9.2)")
				.isEqualTo(ACCESS_TOKEN_SECONDS);
		assertThat(this.jwtTokenProvider.getRefreshTokenValidity())
				.as("refresh_token.expires_at 을 계산할 때 쓴다 (sp-docs/domain-model.md §2.2)")
				.isEqualTo(Duration.ofSeconds(REFRESH_TOKEN_SECONDS));
	}

	@Test
	@DisplayName("grantType 이 Bearer 다")
	void grant_type_은_Bearer_다() {
		assertThat(this.jwtTokenProvider.issue(7L, Role.USER).grantType()).isEqualTo("Bearer");
	}

	@Test
	@DisplayName("공개키만 가진 쪽이 서명을 검증할 수 있다")
	void 공개키로_검증된다() {
		TokenResponse response = this.jwtTokenProvider.issue(7L, Role.USER);

		JwtDecoder publicKeyOnlyDecoder = publicKeyOnlyDecoder();

		assertThat(publicKeyOnlyDecoder.decode(response.accessToken()).getSubject()).isEqualTo("7");
		assertThat(publicKeyOnlyDecoder.decode(response.refreshToken()).getSubject()).isEqualTo("7");
	}

	@Test
	@DisplayName("payload 를 변조한 토큰은 검증에 실패한다")
	void 변조된_토큰은_검증_실패한다() {
		String token = this.jwtTokenProvider.issue(7L, Role.USER).accessToken();

		String tampered = tamperSubject(token);
		assertThat(tampered).isNotEqualTo(token);

		assertThatThrownBy(() -> publicKeyOnlyDecoder().decode(tampered))
				.isInstanceOf(JwtException.class);
	}

	@Test
	@DisplayName("개인키 경로가 없으면 기동이 실패한다")
	void 개인키가_없으면_기동_실패한다() {
		jwtConfigRunner().run(context -> assertThat(context)
				.as("기본값을 두면 키 없이도 기동해버린다 (sp-docs/security.md §3)")
				.hasFailed());

		jwtConfigRunner()
				.withPropertyValues("jwt.private-key-location=")
				.run(context -> assertThat(context).hasFailed());
	}

	@Test
	@DisplayName("개인키 파일이 없으면 기동이 실패한다 — 조용히 넘어가지 않는다")
	void 개인키_파일이_없으면_기동_실패한다() {
		jwtConfigRunner()
				.withPropertyValues("jwt.private-key-location=file:/no/such/dir/private.pem")
				.run(context -> assertThat(context)
						.hasFailed()
						.getFailure()
						.hasRootCauseInstanceOf(IllegalStateException.class));
	}

	@Test
	@DisplayName("개인키가 주입되면 서명기와 검증기가 만들어진다")
	void 개인키가_있으면_빈이_만들어진다() {
		jwtConfigRunner()
				.withPropertyValues("jwt.private-key-location=" + TestRsaKeys.privateKeyLocation())
				.run(context -> assertThat(context)
						.hasNotFailed()
						.hasSingleBean(JwtEncoder.class)
						.hasSingleBean(JwtDecoder.class));
	}

	/**
	 * {@link JwtConfig} 만 올린 컨텍스트. {@code PropertyPlaceholderAutoConfiguration} 을 함께
	 * 올려 실제 기동과 같은 placeholder 해석 규칙(해석 못 하면 실패)을 쓴다.
	 */
	private ApplicationContextRunner jwtConfigRunner() {
		return new ApplicationContextRunner()
				.withConfiguration(AutoConfigurations.of(PropertyPlaceholderAutoConfiguration.class))
				.withUserConfiguration(JwtConfig.class);
	}

	private JwtDecoder publicKeyOnlyDecoder() {
		return NimbusJwtDecoder.withPublicKey(TestRsaKeys.publicKey())
				.signatureAlgorithm(SignatureAlgorithm.RS256)
				.build();
	}

	private long validitySeconds(String token) throws ParseException {
		SignedJWT jwt = SignedJWT.parse(token);
		long issuedAt = jwt.getJWTClaimsSet().getIssueTime().getTime();
		long expiresAt = jwt.getJWTClaimsSet().getExpirationTime().getTime();
		return (expiresAt - issuedAt) / 1000L;
	}

	/** 서명은 그대로 두고 payload 의 sub 만 바꾼다. 서명 검증이 살아 있으면 실패해야 한다. */
	private String tamperSubject(String token) {
		String[] parts = token.split("\\.");
		String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
		String tamperedPayload = payload.replace("\"sub\":\"7\"", "\"sub\":\"8\"");
		assertThat(tamperedPayload).as("변조 대상 claim 을 찾았다").isNotEqualTo(payload);

		String encoded = Base64.getUrlEncoder().withoutPadding()
				.encodeToString(tamperedPayload.getBytes(StandardCharsets.UTF_8));
		return parts[0] + "." + encoded + "." + parts[2];
	}

}
