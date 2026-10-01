package com.example.auth.global.config;

import com.example.auth.global.security.SecurityErrorResponder;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * 경로별 인가. 업무 API 는 sp-docs/api-contract.md §2, 인프라 경로는 sp-docs/security.md §5.1.1
 * 이 정본이다.
 *
 * <p><b>선언하지 않은 경로는 401 이 된다.</b> {@code spring-boot-starter-security} 가 있으면 전
 * 경로에 인증이 요구되므로, 공개 경로를 빠뜨리면 조용히 막힌다 (sp-docs/security.md §5.1.1).
 * 그래서 {@code anyRequest()} 를 {@code authenticated()} 로 둔다 — 새 경로가 생겼을 때 열린
 * 상태가 아니라 막힌 상태가 기본값이 되도록.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final SecurityErrorResponder securityErrorResponder;

	@Bean
	public SecurityFilterChain securityFilterChain(
			HttpSecurity http, CorsConfigurationSource corsConfigurationSource) throws Exception {

		http
				// Stateless REST API 이므로 CSRF 토큰을 쓰지 않는다 (sp-docs/security.md §1)
				.csrf(AbstractHttpConfigurer::disable)
				.cors(cors -> cors.configurationSource(corsConfigurationSource))
				// 토큰 인증만 쓴다. 폼 로그인을 남겨두면 인가 실패가 /login 리다이렉트로 보인다
				.formLogin(AbstractHttpConfigurer::disable)
				.httpBasic(AbstractHttpConfigurer::disable)
				// 로그아웃은 POST /api/v1/auth/logout 이다 (sp-docs/api-contract.md §2.1).
				// Security 기본 /logout 엔드포인트를 추가로 열지 않는다
				.logout(AbstractHttpConfigurer::disable)
				.sessionManagement(session -> session
						.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				// 인가 실패 시 원 요청을 세션에 저장하지 않는다. 저장하면 STATELESS 인데도
				// 세션이 생긴다
				.requestCache(RequestCacheConfigurer::disable)

				.authorizeHttpRequests(auth -> auth
						// --- 인프라 경로 (sp-docs/security.md §5.1.1) ---
						// prod 프로파일에서 springdoc 자체를 끄는 것은 AU-11 이다
						.requestMatchers("/swagger-ui.html", "/swagger-ui/**").permitAll()
						.requestMatchers("/v3/api-docs", "/v3/api-docs/**").permitAll()
						.requestMatchers("/actuator/health").permitAll()
						// health 외의 actuator 는 노출 자체를 막는다
						.requestMatchers("/actuator/**").denyAll()

						// --- 계정 (sp-docs/api-contract.md §2.2) ---
						// ★ /accounts/me 를 /accounts 보다 먼저 선언한다. 먼저 선언된 규칙이
						// 이기므로 순서를 바꾸면 내 계정이 무인증으로 열린다
						.requestMatchers("/api/v1/accounts/me", "/api/v1/accounts/me/**").authenticated()
						.requestMatchers(HttpMethod.POST, "/api/v1/accounts").permitAll()
						.requestMatchers(HttpMethod.GET, "/api/v1/accounts/check-email").permitAll()

						// --- 인증 (sp-docs/api-contract.md §2.1) ---
						.requestMatchers(HttpMethod.POST, "/api/v1/auth/login", "/api/v1/auth/reissue")
						.permitAll()
						.requestMatchers(HttpMethod.POST, "/api/v1/auth/logout").authenticated()

						.anyRequest().authenticated())

				// 자기가 발급한 토큰을 검증한다. JwtDecoder 는 JwtConfig 가 만든다
				.oauth2ResourceServer(oauth2 -> oauth2
						.jwt(Customizer.withDefaults())
						.authenticationEntryPoint(this.securityErrorResponder)
						.accessDeniedHandler(this.securityErrorResponder))

				// A001 / A004 를 공통 응답 형식으로 내보낸다
				.exceptionHandling(exception -> exception
						.authenticationEntryPoint(this.securityErrorResponder)
						.accessDeniedHandler(this.securityErrorResponder));

		return http.build();
	}

	/** BCrypt, strength 10 (sp-docs/security.md §1). 비밀번호를 다루는 서비스는 auth 하나다. */
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(10);
	}

	/**
	 * CORS 화이트리스트. <b>{@code *} 를 쓰지 않는다</b> (sp-docs/security.md §1).
	 *
	 * <p><b>허용 오리진 목록은 정본에 없다.</b> sp-docs/security.md §1 은 "서비스별 화이트리스트로
	 * 관리, {@code *} 금지"만 정하고 목록 자체를 정하지 않았다. 그래서 값을 코드나 커밋되는
	 * 설정에 박지 않고 {@code cors.allowed-origins} 로 주입받는다. <b>기본값을 두지 않으므로
	 * 값이 없으면 기동이 실패한다</b> — 임의의 기본값을 두면 나중에 그 값이 정책인지 임시값인지
	 * 구분할 수 없다.
	 *
	 * <p>{@code *} 가 섞여 들어오면 기동을 실패시킨다. 값이 환경에서 오므로, 정본의 금지 규칙을
	 * 지키는 지점은 여기뿐이다.
	 */
	@Bean
	public CorsConfigurationSource corsConfigurationSource(
			@Value("${cors.allowed-origins}") List<String> allowedOrigins) {

		if (allowedOrigins.isEmpty()) {
			throw new IllegalStateException(
					"cors.allowed-origins 가 비어 있다. 허용 오리진을 외부에서 주입한다 "
							+ "(sp-docs/security.md §1).");
		}
		allowedOrigins.stream()
				.filter(origin -> origin.contains("*"))
				.findFirst()
				.ifPresent(origin -> {
					throw new IllegalStateException(
							"CORS 허용 오리진에 와일드카드를 쓸 수 없다: " + origin
									+ " (sp-docs/security.md §1)");
				});

		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(allowedOrigins);
		// api-contract.md §2 가 쓰는 메서드. OPTIONS 는 preflight 처리에 쓰여 목록에 넣지 않는다
		configuration.setAllowedMethods(List.of(
				HttpMethod.GET.name(), HttpMethod.POST.name(),
				HttpMethod.PATCH.name(), HttpMethod.DELETE.name()));
		configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
		// 토큰은 Authorization 헤더로 오므로 쿠키를 허용할 이유가 없다
		configuration.setAllowCredentials(false);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

}
