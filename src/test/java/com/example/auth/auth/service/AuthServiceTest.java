package com.example.auth.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;

import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.Role;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.auth.dto.LoginRequest;
import com.example.auth.auth.dto.ReissueRequest;
import com.example.auth.auth.dto.TokenResponse;
import com.example.auth.auth.entity.RefreshToken;
import com.example.auth.auth.repository.RefreshTokenRepository;
import com.example.auth.global.error.BusinessException;
import com.example.auth.global.error.ErrorCode;
import com.example.auth.global.security.JwtTokenProvider;
import com.example.auth.support.TestRsaKeys;
import com.example.auth.support.TestTokens;
import com.nimbusds.jwt.SignedJWT;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * sp-docs/plan/phase1.md §4 AU-06·AU-07 의 "검증" 표 중 저장·Claim·회전 쪽을 테스트로 옮긴
 * 것이다. HTTP 상태·응답 본문은 {@link com.example.auth.auth.controller.AuthControllerTest}
 * 가 본다.
 *
 * <p>정본은 sp-docs/requirements/member.md §1 (MR-04·MR-05·MR-06) §6, sp-docs/security.md §4,
 * sp-docs/domain-model.md §2.2 다.
 *
 * <p>실제 {@code PasswordEncoder}(BCrypt strength 10)·{@code JwtTokenProvider}·H2 를 함께 쓴다.
 * 해싱이나 서명을 스텁으로 바꾸면 "저장된 해시로 로그인이 된다"와 "발급된 토큰의 claim 이
 * 계약과 같다"가 검증되지 않는다.
 *
 * <p><b>여기서 만드는 것은 계정 행 하나뿐이다 — 프로필은 없다.</b> "계정만 있고 프로필이 없는
 * 상태"에서 로그인이 되어야 하므로(sp-docs/requirements/member.md §3 규칙 3) 이 테스트 전체가
 * 그 조건을 쓴다.
 */
@SpringBootTest
@ActiveProfiles("test")
class AuthServiceTest {

	private static final String RAW_PASSWORD = "Passw0rd!";

	/** V3 seed 의 계정 (sp-docs/requirements/member.md §10.1). 테스트가 만든 것이 아니다. */
	private static final String ADMIN_EMAIL = "admin@example.com";

	/** sp-docs/api-contract.md §6 의 claim 전체. 하나라도 늘거나 줄면 계약이 깨진다. */
	private static final String[] CONTRACT_CLAIMS = {"sub", "role", "iss", "iat", "exp"};

	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	@Autowired
	private AuthService authService;

	@Autowired
	private AccountRepository accountRepository;

	@Autowired
	private RefreshTokenRepository refreshTokenRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	/** {@link #세_실패_경로가_matches_를_한_번씩_한다} 가 서비스를 직접 만들 때 쓴다. */
	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	/**
	 * 회전 전후를 비교할 픽스처를 만들 때 쓴다 ({@link #저장된_세션을_만든다}).
	 *
	 * <p>애플리케이션의 서명 키를 그대로 쓰기 위해 빈을 받는다 — 테스트가 따로 키를 만들면
	 * "서명은 옳은 옛 토큰"이 아니라 그냥 잘못된 토큰이 된다.
	 */
	@Autowired
	private JwtEncoder jwtEncoder;

	/**
	 * <b>seed 행은 남긴다.</b> H2 는 테스트 클래스 사이에 공유되므로
	 * ({@code DB_CLOSE_DELAY=-1}, sp-docs/tech-stack.md §5.3) 여기서 지우면
	 * {@code AdminSeedTest} 가 자기와 무관한 이유로 깨진다.
	 *
	 * <p>{@code fk_refresh_token_account} 가 있으므로 토큰을 먼저 지운다.
	 */
	@AfterEach
	void 정리() {
		this.refreshTokenRepository.deleteAll();
		this.refreshTokenRepository.flush();
		this.accountRepository.deleteAll(this.accountRepository.findAll().stream()
				.filter(account -> !ADMIN_EMAIL.equals(account.getEmail()))
				.toList());
	}

	@Test
	@DisplayName("정상 로그인은 accessToken·refreshToken 을 담은 TokenResponse 를 돌려준다")
	void 정상_로그인() {
		계정을_만든다("user@example.com");

		TokenResponse response = this.authService.login(로그인("user@example.com", RAW_PASSWORD));

		assertThat(response.grantType()).isEqualTo("Bearer");
		assertThat(response.accessToken()).isNotBlank();
		assertThat(response.refreshToken()).isNotBlank();
		assertThat(response.accessTokenExpiresIn()).isPositive();
	}

	@Test
	@DisplayName("정상 로그인 후 refresh_token 이 1행이고 저장값이 응답의 refreshToken 과 같다")
	void 로그인은_refresh_token_을_저장한다() {
		Account account = 계정을_만든다("store@example.com");
		LocalDateTime 로그인_전 = LocalDateTime.now();

		TokenResponse response = this.authService.login(로그인("store@example.com", RAW_PASSWORD));

		List<RefreshToken> rows = this.refreshTokenRepository.findAll();
		assertThat(rows).hasSize(1);
		assertThat(rows.get(0).getAccountId()).isEqualTo(account.getId());
		assertThat(rows.get(0).getToken())
				.as("AU-07 의 재발급이 이 저장값과 대조한다 (sp-docs/security.md §4)")
				.isEqualTo(response.refreshToken());
		assertThat(rows.get(0).getExpiresAt())
				.as("Refresh Token 만료는 14일이다 (sp-docs/security.md §1)")
				.isAfter(로그인_전.plusDays(13))
				.isBefore(로그인_전.plusDays(15));
	}

	@Test
	@DisplayName("같은 계정으로 재로그인해도 refresh_token 은 1행이고 id 가 그대로다")
	void 재로그인해도_1행이고_id_가_같다() {
		Account account = 계정을_만든다("relogin@example.com");

		this.authService.login(로그인("relogin@example.com", RAW_PASSWORD));
		Long 첫_로그인의_id = this.refreshTokenRepository.findAll().get(0).getId();

		TokenResponse second = this.authService.login(로그인("relogin@example.com", RAW_PASSWORD));

		List<RefreshToken> rows = this.refreshTokenRepository.findAll();
		assertThat(rows)
				.as("계정당 1행이다 (sp-docs/domain-model.md §2.2)")
				.hasSize(1);
		assertThat(rows.get(0).getAccountId()).isEqualTo(account.getId());
		assertThat(rows.get(0).getToken()).isEqualTo(second.refreshToken());
		assertThat(rows.get(0).getId())
				.as("갱신이지 재삽입이 아니다. 지우고 다시 넣으면 로그인마다 id 가 올라간다 "
						+ "(sp-docs/plan/phase1.md §4 AU-06)")
				.isEqualTo(첫_로그인의_id);
	}

	/**
	 * "값이 교체된다"를 결정적으로 본다.
	 *
	 * <p>{@link #재로그인해도_1행이고_id_가_같다} 만으로는 교체를 증명하지 못한다 — 같은 초 안에 두 번
	 * 로그인하면 claim 이 모두 같아(sp-docs/api-contract.md §6 에 {@code jti} 가 없다) 두 토큰의
	 * 문자열이 같아진다. 그래서 <b>다른 값이 들어 있는 행</b>을 먼저 심고 그것이 사라지는지 본다.
	 */
	@Test
	@DisplayName("이미 행이 있으면 옛 토큰 값이 사라지고 같은 행이 새 값으로 교체된다")
	void 기존_행의_값이_교체된다() {
		Account account = 계정을_만든다("replace@example.com");
		String 옛_토큰 = jwtShapedToken("previous");
		Long 옛_행의_id = this.refreshTokenRepository.saveAndFlush(RefreshToken.builder()
				.accountId(account.getId())
				.token(옛_토큰)
				.expiresAt(LocalDateTime.now().plusDays(1))
				.build()).getId();

		TokenResponse response = this.authService.login(로그인("replace@example.com", RAW_PASSWORD));

		List<RefreshToken> rows = this.refreshTokenRepository.findAll();
		assertThat(rows).hasSize(1);
		assertThat(rows.get(0).getId())
				.as("같은 행을 갱신한다 (sp-docs/plan/phase1.md §4 AU-06)")
				.isEqualTo(옛_행의_id);
		assertThat(rows.get(0).getToken())
				.isEqualTo(response.refreshToken())
				.isNotEqualTo(옛_토큰);
		assertThat(rows.get(0).getExpiresAt())
				.as("만료도 새 발급 기준으로 바뀐다")
				.isAfter(LocalDateTime.now().plusDays(13));
	}

	@Test
	@DisplayName("비밀번호가 틀리면 refresh_token 에 행이 생기지 않고 기존 행도 그대로다")
	void 로그인_실패는_refresh_token_을_건드리지_않는다() {
		Account account = 계정을_만든다("fail@example.com");

		assertThatThrownBy(() -> this.authService.login(로그인("fail@example.com", "Other1!pw")))
				.isInstanceOf(BusinessException.class);

		assertThat(this.refreshTokenRepository.findAll())
				.as("검증과 저장이 한 트랜잭션이므로 실패하면 아무것도 쓰이지 않는다")
				.isEmpty();

		// 이미 로그인해 둔 세션을 실패한 로그인 시도가 지우지도 않는다
		String 살아있는_토큰 = jwtShapedToken("existing");
		this.refreshTokenRepository.saveAndFlush(RefreshToken.builder()
				.accountId(account.getId())
				.token(살아있는_토큰)
				.expiresAt(LocalDateTime.now().plusDays(1))
				.build());

		assertThatThrownBy(() -> this.authService.login(로그인("fail@example.com", "Other1!pw")))
				.isInstanceOf(BusinessException.class);

		assertThat(this.refreshTokenRepository.findAll())
				.singleElement()
				.extracting(RefreshToken::getToken)
				.isEqualTo(살아있는_토큰);
	}

	/**
	 * <b>이 항목의 핵심 단언이다.</b> 둘이 갈리면 이메일 존재 여부를 알려주는 열거 취약점이 된다
	 * (sp-docs/plan/phase1.md §4 AU-06).
	 */
	@Test
	@DisplayName("비밀번호 불일치와 없는 이메일이 같은 AU003·같은 메시지다")
	void 비밀번호_불일치와_없는_이메일이_구별되지_않는다() {
		계정을_만든다("exists@example.com");

		BusinessException 비밀번호_불일치 = 로그인에_실패한다("exists@example.com", "Other1!pw");
		BusinessException 없는_이메일 = 로그인에_실패한다("nobody@example.com", RAW_PASSWORD);

		assertThat(비밀번호_불일치.getErrorCode()).isEqualTo(ErrorCode.LOGIN_FAILED);
		assertThat(없는_이메일.getErrorCode()).isEqualTo(비밀번호_불일치.getErrorCode());
		assertThat(없는_이메일.getMessage()).isEqualTo(비밀번호_불일치.getMessage());
		assertThat(ErrorCode.LOGIN_FAILED.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
		assertThat(ErrorCode.LOGIN_FAILED.getCode()).isEqualTo("AU003");
	}

	/**
	 * <b>응답 본문을 맞추는 것으로는 부족하다</b> (sp-docs/security.md §4.1). 계정이 없을 때
	 * BCrypt 비교를 건너뛰면 그 경로만 48ms 빨라져 이메일 존재 여부가 드러난다. 탈퇴 계정도
	 * 같다 — 거기서 건너뛰면 "존재하되 탈퇴했다"를 알려준다.
	 *
	 * <p>시간이 아니라 <b>{@code matches} 호출 횟수</b>로 본다. 메커니즘을 직접 보므로 기계
	 * 속도와 무관하게 결정적이다. 시간 쪽은 {@link #세_실패_경로의_시간이_같은_자리수다} 가 본다.
	 */
	@Test
	@DisplayName("세 실패 경로가 모두 matches 를 정확히 한 번 수행한다")
	void 세_실패_경로가_matches_를_한_번씩_한다() {
		계정을_만든다("counting-active@example.com");
		탈퇴한_계정을_만든다("counting-withdrawn@example.com");

		CountingPasswordEncoder counting = new CountingPasswordEncoder(this.passwordEncoder);
		// 더미 해시를 만드는 encode 는 생성자에서 한 번 일어난다 — matches 횟수는 0 에서 시작한다
		AuthService service = new AuthService(
				this.accountRepository, this.refreshTokenRepository, counting, this.jwtTokenProvider);

		Map<String, LoginRequest> 실패_경로 = new LinkedHashMap<>();
		실패_경로.put("없는 이메일", 로그인("nobody@example.com", RAW_PASSWORD));
		실패_경로.put("탈퇴 계정", 로그인("counting-withdrawn@example.com", RAW_PASSWORD));
		실패_경로.put("비밀번호 불일치", 로그인("counting-active@example.com", "Other1!pw"));

		실패_경로.forEach((이름, request) -> {
			counting.reset();
			assertThatThrownBy(() -> service.login(request))
					.as(이름)
					.isInstanceOf(BusinessException.class);
			assertThat(counting.matchesCalls())
					.as("%s — 0 이면 비교를 건너뛴 것이고 시간으로 드러난다", 이름)
					.isEqualTo(1);
		});
	}

	/**
	 * 검증표의 "세 경로가 같은 자리수다" 행이다.
	 *
	 * <p><b>절대 시간을 단언하지 않는다.</b> BCrypt 비교 한 번의 비용을 같은 실행에서 재
	 * 기준으로 쓰고, 세 경로가 그 기준의 1/4 이상인지만 본다. 양쪽 모두 <b>최소값</b>을 쓰므로
	 * GC·스케줄링으로 위로 튀는 잡음에 둔감하다. 비교를 건너뛴 경로는 1ms 미만이므로
	 * (측정값 0.0ms vs 48.5ms, sp-docs/security.md §4.1) 여유를 둬도 잡힌다.
	 */
	@Test
	@DisplayName("세 실패 경로의 응답 시간이 같은 자리수다")
	void 세_실패_경로의_시간이_같은_자리수다() {
		계정을_만든다("timing-active@example.com");
		탈퇴한_계정을_만든다("timing-withdrawn@example.com");
		String 아는_해시 = this.passwordEncoder.encode(RAW_PASSWORD);

		// 워밍업. 첫 호출은 JIT·클래스 로딩 때문에 느려 기준을 부풀린다
		this.passwordEncoder.matches("Other1!pw", 아는_해시);
		로그인에_실패한다("nobody@example.com", RAW_PASSWORD);

		long 기준 = 최소_소요시간(() -> this.passwordEncoder.matches("Other1!pw", 아는_해시));
		long 없는_이메일 = 최소_소요시간(() -> 로그인에_실패한다("nobody@example.com", RAW_PASSWORD));
		long 탈퇴_계정 = 최소_소요시간(() -> 로그인에_실패한다("timing-withdrawn@example.com", RAW_PASSWORD));
		long 비밀번호_불일치 = 최소_소요시간(() -> 로그인에_실패한다("timing-active@example.com", "Other1!pw"));

		assertThat(List.of(없는_이메일, 탈퇴_계정, 비밀번호_불일치))
				.as("한 경로만 눈에 띄게 빠르면 matches 를 건너뛴 것이다 (sp-docs/security.md §4.1)")
				.allSatisfy(소요시간 -> assertThat(소요시간).isGreaterThan(기준 / 4));
	}

	@Test
	@DisplayName("탈퇴한 계정은 비밀번호가 맞아도 로그인할 수 없다")
	void 탈퇴_계정은_로그인할_수_없다() {
		Account account = 계정을_만든다("bye@example.com");
		account.withdraw();
		this.accountRepository.saveAndFlush(account);

		BusinessException thrown = 로그인에_실패한다("bye@example.com", RAW_PASSWORD);

		assertThat(thrown.getErrorCode())
				.as("검사하지 않으면 탈퇴 계정이 토큰을 계속 받는다 "
						+ "(sp-docs/requirements/member.md §3 규칙 5)")
				.isEqualTo(ErrorCode.LOGIN_FAILED);
		assertThat(thrown.getErrorCode().getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
		assertThat(this.refreshTokenRepository.findAll()).isEmpty();
	}

	/**
	 * claim 집합을 <b>"정확히 이 다섯 개"</b>로 고정한다. {@code nickname} 이 없는지만 보면 다른
	 * claim 이 늘어나는 것을 놓친다 — §6 은 세 서비스가 공유하는 계약이다.
	 *
	 * <p>{@code JwtTokenProviderTest} 가 같은 단언을 하지만 거기서 보는 것은 발급기 단독 호출
	 * 결과다. <b>로그인이 실제로 내보낸 토큰</b>에 대해 다시 본다.
	 */
	@Test
	@DisplayName("로그인이 발급한 토큰의 claim 이 계정 정보와 일치하고 nickname 이 없다")
	void 발급된_토큰의_claim() throws Exception {
		Account account = 계정을_만든다("claim@example.com");

		TokenResponse response = this.authService.login(로그인("claim@example.com", RAW_PASSWORD));

		for (String token : List.of(response.accessToken(), response.refreshToken())) {
			Map<String, Object> claims = SignedJWT.parse(token).getJWTClaimsSet().getClaims();

			assertThat(claims.get("sub"))
					.as("sub 은 account.id 의 문자열이다 (sp-docs/api-contract.md §6)")
					.isEqualTo(String.valueOf(account.getId()));
			assertThat(claims.get("role")).isEqualTo(Role.USER.name());
			assertThat(claims.get("iss")).isEqualTo("auth-service");
			assertThat(claims)
					.as("auth 는 닉네임을 소유하지 않는다 (sp-docs/api-contract.md §6)")
					.doesNotContainKey("nickname")
					.containsOnlyKeys(CONTRACT_CLAIMS);
		}
	}

	// --- AU-07 재발급·로그아웃 (sp-docs/requirements/member.md §1 MR-05·MR-06, §6) ---

	@Test
	@DisplayName("정상 재발급은 새 토큰 2개를 돌려주고 같은 행의 저장값이 새 것으로 교체된다")
	void 정상_재발급() {
		Account account = 계정을_만든다("reissue@example.com");
		RefreshToken 옛_행 = 저장된_세션을_만든다(account, 조금_전());
		String 옛_토큰 = 옛_행.getToken();

		TokenResponse response = this.authService.reissue(new ReissueRequest(옛_토큰));

		assertThat(response.grantType()).isEqualTo("Bearer");
		assertThat(response.accessToken()).isNotBlank();
		assertThat(response.refreshToken()).isNotBlank().isNotEqualTo(옛_토큰);

		List<RefreshToken> rows = this.refreshTokenRepository.findAll();
		assertThat(rows)
				.as("계정당 1행이다 (sp-docs/domain-model.md §2.2)")
				.hasSize(1);
		assertThat(rows.get(0).getId())
				.as("회전은 조건부 UPDATE 다. 지우고 다시 넣으면 id 가 올라간다")
				.isEqualTo(옛_행.getId());
		assertThat(rows.get(0).getToken()).isEqualTo(response.refreshToken());
		assertThat(rows.get(0).getExpiresAt())
				.as("만료도 새 발급 기준으로 바뀐다 (14일, sp-docs/security.md §1)")
				.isAfter(LocalDateTime.now().plusDays(13));
	}

	/**
	 * <b>이 항목의 핵심 단언 하나다.</b> 회전이 조건부 UPDATE 이고 0행이면 실패한다는 것을
	 * 서비스 경로에서 본다 — 제시된 토큰이 저장값과 다르면 거부되어야 한다
	 * (sp-docs/plan/phase1.md §4 AU-07).
	 *
	 * <p>{@code RefreshToken.renew()} 로 바꿔 끼우면 이 테스트가 깨진다. 그 메서드는 조건 없이
	 * 값을 덮으므로 이미 회전된 옛 토큰으로도 재발급이 성립한다.
	 */
	@Test
	@DisplayName("회전 뒤 이전 Refresh Token 으로 재발급하면 실패한다")
	void 이전_토큰_재사용은_실패한다() {
		Account account = 계정을_만든다("rotated@example.com");
		String 이전_토큰 = 저장된_세션을_만든다(account, 조금_전()).getToken();

		TokenResponse 첫_재발급 = this.authService.reissue(new ReissueRequest(이전_토큰));
		assertThat(첫_재발급.refreshToken()).isNotEqualTo(이전_토큰);

		BusinessException thrown = 재발급에_실패한다(이전_토큰);

		assertThat(thrown.getErrorCode()).isEqualTo(ErrorCode.INVALID_TOKEN);
		assertThat(this.refreshTokenRepository.findAll())
				.as("거부된 재발급이 저장값을 건드리지 않는다")
				.singleElement()
				.extracting(RefreshToken::getToken)
				.isEqualTo(첫_재발급.refreshToken());
	}

	/**
	 * <b>저장값 대조가 유일한 방어선이다.</b> Access Token 은 Refresh Token 과 같은 키로 서명되고
	 * claim 집합도 같으며 만료도 지나지 않았다 — 다른 것은 {@code exp} 하나다
	 * (sp-docs/api-contract.md §6). 그래서 서명·만료 검증만으로는 둘을 구별할 수 없고,
	 * {@code refresh_token} 저장값과의 대조가 그것을 막는다.
	 */
	@Test
	@DisplayName("서명과 만료가 멀쩡해도 저장값과 다른 토큰은 거부된다 — 같은 로그인의 Access Token")
	void 저장값과_다른_토큰은_거부된다() {
		계정을_만든다("mismatch@example.com");
		TokenResponse 로그인 = this.authService.login(로그인("mismatch@example.com", RAW_PASSWORD));

		BusinessException thrown = 재발급에_실패한다(로그인.accessToken());

		assertThat(thrown.getErrorCode()).isEqualTo(ErrorCode.INVALID_TOKEN);
		assertThat(this.refreshTokenRepository.findAll())
				.singleElement()
				.extracting(RefreshToken::getToken)
				.isEqualTo(로그인.refreshToken());
	}

	@Test
	@DisplayName("만료된 Refresh Token 은 A003 으로 거부된다")
	void 만료된_토큰은_거부된다() {
		Account account = 계정을_만든다("expired@example.com");
		// 15일 전 발급으로 서명하면 exp 가 하루 전이다. 디코더의 기본 clock skew 가 60초이므로
		// (측정: JwtTimestampValidator) 그보다 충분히 과거여야 만료로 판정된다.
		// 저장값과 일치시킨다 — 만료가 유일한 거부 사유가 되도록
		String 만료된_토큰 = 저장된_세션을_만든다(
				account, Instant.now().minus(Duration.ofDays(15))).getToken();

		BusinessException thrown = 재발급에_실패한다(만료된_토큰);

		assertThat(thrown.getErrorCode())
				.as("만료는 A003 이다 (sp-docs/api-contract.md §8.1)")
				.isEqualTo(ErrorCode.EXPIRED_TOKEN);
	}

	@Test
	@DisplayName("서명이 변조된 Refresh Token 은 A002 로 거부된다")
	void 변조된_토큰은_거부된다() {
		Account account = 계정을_만든다("tampered@example.com");
		String 저장된_토큰 = 저장된_세션을_만든다(account, 조금_전()).getToken();

		BusinessException thrown = 재발급에_실패한다(TestTokens.tamperSignature(저장된_토큰));

		assertThat(thrown.getErrorCode())
				.as("서명 오류는 A002 다 (sp-docs/api-contract.md §8.1)")
				.isEqualTo(ErrorCode.INVALID_TOKEN);
		assertThat(this.refreshTokenRepository.findAll())
				.singleElement()
				.extracting(RefreshToken::getToken)
				.isEqualTo(저장된_토큰);
	}

	@Test
	@DisplayName("Refresh Token 이 비어 있으면 A001 이다")
	void 토큰이_비어_있으면_A001() {
		for (String 없는_값 : new String[] {null, "", "   "}) {
			assertThat(재발급에_실패한다(없는_값).getErrorCode())
					.as("제시된 토큰이 없다 — A002(유효하지 않은 토큰)가 아니다 "
							+ "(sp-docs/api-contract.md §8.1)")
					.isEqualTo(ErrorCode.UNAUTHORIZED);
		}
	}

	/**
	 * <b>이 항목의 핵심 단언 하나다.</b> 행을 남긴 채 계정만 탈퇴시켜, {@code deleted} 검사가
	 * 유일한 방어선인 상태를 만든다. 검사가 없으면 탈퇴 계정이 14일간 토큰을 갱신한다
	 * (sp-docs/requirements/member.md §3 규칙 5, §6).
	 *
	 * <p><b>AU-06 이 남긴 경합이 여기서 닫힌다.</b> 로그인이 {@code authenticate()} 뒤에 커밋된
	 * 탈퇴와 겹쳐 탈퇴 계정 행을 INSERT 하더라도, 이 검사가 있는 한 그 행으로 재발급받을 수 없다
	 * (sp-docs/plan/phase1.md §4 AU-07).
	 */
	@Test
	@DisplayName("탈퇴 계정의 유효한 Refresh Token 으로는 재발급받을 수 없다")
	void 탈퇴_계정은_재발급받을_수_없다() {
		Account account = 계정을_만든다("withdrawn-reissue@example.com");
		String 유효한_토큰 = 저장된_세션을_만든다(account, 조금_전()).getToken();

		account.withdraw();
		this.accountRepository.saveAndFlush(account);

		BusinessException thrown = 재발급에_실패한다(유효한_토큰);

		assertThat(thrown.getErrorCode()).isEqualTo(ErrorCode.INVALID_TOKEN);
		assertThat(this.refreshTokenRepository.findAll())
				.as("거부된 재발급은 저장값을 건드리지 않는다")
				.singleElement()
				.extracting(RefreshToken::getToken)
				.isEqualTo(유효한_토큰);
	}

	/**
	 * 정본 §6 의 R1/D1/R2 중 <b>D1 이 커밋된 뒤의 R2</b> 를 본다. 이 상태에서 재발급이 성공하면
	 * 삭제한 행이 되살아나 "탈퇴 후 최대 30분"이라는 경계가 무너진다.
	 *
	 * <p>R1 과 R2 사이에 D1 이 끼어드는 실제 인터리빙은
	 * {@code RefreshTokenRepositoryTest.삭제된_행에_회전하면_0행이고_되살아나지_않는다} 가 조건부
	 * UPDATE 수준에서 본다. 여기서는 <b>서비스 경로가 그 결과를 실패로 바꾸는지</b>를 본다.
	 */
	@Test
	@DisplayName("탈퇴가 커밋된 뒤의 재발급은 실패하고 refresh_token 행이 되살아나지 않는다")
	void 탈퇴_커밋_후_재발급() {
		Account account = 계정을_만든다("race@example.com");
		String 옛_토큰 = 저장된_세션을_만든다(account, 조금_전()).getToken();

		// 탈퇴 1단계. account.deleted = true 와 RefreshToken 삭제가 한 트랜잭션이다
		// (sp-docs/api-contract.md §2.2). 그 경로 자체는 AU-09 가 만든다 —
		// 여기서는 그것이 남기는 상태만 만든다
		account.withdraw();
		this.accountRepository.saveAndFlush(account);
		this.refreshTokenRepository.findByAccountId(account.getId())
				.ifPresent(this.refreshTokenRepository::delete);
		this.refreshTokenRepository.flush();

		BusinessException thrown = 재발급에_실패한다(옛_토큰);

		assertThat(thrown.getErrorCode()).isEqualTo(ErrorCode.INVALID_TOKEN);
		assertThat(this.refreshTokenRepository.findAll())
				.as("되살아나면 탈퇴 계정에 14일짜리 RefreshToken 이 생긴다 "
						+ "(sp-docs/requirements/member.md §6 의 R2)")
				.isEmpty();
	}

	@Test
	@DisplayName("로그아웃은 저장된 Refresh Token 을 지우고, 행이 없어도 그대로 끝난다")
	void 로그아웃은_행을_지운다() {
		Account account = 계정을_만든다("logout@example.com");
		저장된_세션을_만든다(account, 조금_전());

		this.authService.logout(account.getId());

		assertThat(this.refreshTokenRepository.findAll()).isEmpty();

		// 이미 지워진 뒤에 다시 불러도 예외가 아니다 — 지울 것이 없을 뿐이다
		this.authService.logout(account.getId());
		assertThat(this.refreshTokenRepository.findAll()).isEmpty();
	}

	@Test
	@DisplayName("로그아웃 후 같은 Refresh Token 으로 재발급하면 실패한다")
	void 로그아웃_후_재발급은_실패한다() {
		Account account = 계정을_만든다("logout-reissue@example.com");
		String 토큰 = 저장된_세션을_만든다(account, 조금_전()).getToken();

		this.authService.logout(account.getId());

		assertThat(재발급에_실패한다(토큰).getErrorCode()).isEqualTo(ErrorCode.INVALID_TOKEN);
		assertThat(this.refreshTokenRepository.findAll())
				.as("거부된 재발급이 행을 다시 만들지 않는다")
				.isEmpty();
	}

	/** 실패 사유를 비교해야 하므로 예외 객체 자체가 필요하다. */
	private BusinessException 재발급에_실패한다(String refreshToken) {
		try {
			this.authService.reissue(new ReissueRequest(refreshToken));
		} catch (BusinessException e) {
			return e;
		}
		return fail("재발급이 실패해야 한다");
	}

	/**
	 * "{@code 발급_시각} 에 로그인해 둔 상태"를 만든다 — {@code refresh_token} 행 하나와 그 토큰.
	 *
	 * <p>토큰은 {@link TestTokens#signed} 로 서명한다. <b>발급 경로를 쓸 수 없다</b> — 같은 초에
	 * 두 번 발급하면 문자열이 같아져 회전 전후를 비교할 수 없기 때문이다
	 * (sp-docs/requirements/member.md §6.2, sp-docs/conventions.md §9.2 의 예외).
	 *
	 * <p>{@code expires_at} 은 그 발급 시각 기준으로 넣는다 — 토큰의 {@code exp} 와 어긋나지
	 * 않게 한다.
	 */
	private RefreshToken 저장된_세션을_만든다(Account account, Instant 발급_시각) {
		Duration validity = this.jwtTokenProvider.getRefreshTokenValidity();
		String token = TestTokens.signed(
				this.jwtEncoder, account.getId(), account.getRole(), 발급_시각, validity);

		return this.refreshTokenRepository.saveAndFlush(RefreshToken.builder()
				.accountId(account.getId())
				.token(token)
				.expiresAt(LocalDateTime.ofInstant(발급_시각.plus(validity), ZoneId.systemDefault()))
				.build());
	}

	/**
	 * 지금과 <b>다른 초</b>. 재발급이 돌려주는 토큰이 저장값과 달라야 회전을 관찰할 수 있다
	 * (sp-docs/requirements/member.md §6.2).
	 */
	private static Instant 조금_전() {
		return Instant.now().minusSeconds(10);
	}

	/** 두 실패를 서로 비교해야 하므로 예외 객체 자체가 필요하다. */
	private BusinessException 로그인에_실패한다(String email, String password) {
		try {
			this.authService.login(로그인(email, password));
		} catch (BusinessException e) {
			return e;
		}
		return fail("로그인이 실패해야 한다");
	}

	private static LoginRequest 로그인(String email, String password) {
		return new LoginRequest(email, password);
	}

	/** 프로필은 만들지 않는다 — auth 는 프로필을 소유하지 않는다. */
	private Account 계정을_만든다(String email) {
		return this.accountRepository.saveAndFlush(Account.builder()
				.email(email)
				// 런타임에 인코딩한다. 해시를 테스트 파일에 적으면 커밋되는 픽스처가 된다
				// (sp-docs/requirements/member.md §10.2)
				.password(this.passwordEncoder.encode(RAW_PASSWORD))
				.build());
	}

	private void 탈퇴한_계정을_만든다(String email) {
		Account account = 계정을_만든다(email);
		account.withdraw();
		this.accountRepository.saveAndFlush(account);
	}

	/** 세 번 재서 가장 짧은 값을 쓴다. 최소값은 위로 튀는 잡음(GC·스케줄링)에 둔감하다. */
	private static long 최소_소요시간(Runnable action) {
		long min = Long.MAX_VALUE;
		for (int i = 0; i < 3; i++) {
			long start = System.nanoTime();
			action.run();
			min = Math.min(min, System.nanoTime() - start);
		}
		return min;
	}

	/**
	 * 발급 토큰과 같은 모양·길이(557자)의 문자열. <b>조립한 값이다.</b>
	 *
	 * <p>발급 경로로 만들면 안 되는 자리에만 쓴다 — {@code jti} 가 없고 {@code iat} 가 초
	 * 단위이므로 같은 계정의 두 발급이 같은 초에 일어나면 문자열이 완전히 같아져 "교체됐다"를
	 * 볼 수 없다 (sp-docs/conventions.md §9.2 의 예외). {@code Thread.sleep} 으로 우회하지 않는다.
	 */
	private static String jwtShapedToken(String marker) {
		String body = marker + "x".repeat(555 - marker.length());
		return body.substring(0, 90) + "." + body.substring(90, 197) + "." + body.substring(197);
	}

	/**
	 * {@code matches} 호출 횟수를 센다. 실제 인코더에 위임하므로 비용도 실제와 같다 —
	 * 스텁으로 바꾸면 "비교를 건너뛰지 않는다"가 검증되지 않는다.
	 */
	private static final class CountingPasswordEncoder implements PasswordEncoder {

		private final PasswordEncoder delegate;
		private int matchesCalls;

		private CountingPasswordEncoder(PasswordEncoder delegate) {
			this.delegate = delegate;
		}

		@Override
		public String encode(CharSequence rawPassword) {
			return this.delegate.encode(rawPassword);
		}

		@Override
		public boolean matches(CharSequence rawPassword, String encodedPassword) {
			this.matchesCalls++;
			return this.delegate.matches(rawPassword, encodedPassword);
		}

		private int matchesCalls() {
			return this.matchesCalls;
		}

		private void reset() {
			this.matchesCalls = 0;
		}

	}

}
