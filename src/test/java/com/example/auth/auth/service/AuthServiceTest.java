package com.example.auth.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;

import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.Role;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.account.repository.AccountTokenRepository;
import com.example.auth.auth.dto.LoginRequest;
import com.example.auth.auth.dto.LogoutRequest;
import com.example.auth.auth.dto.ReissueRequest;
import com.example.auth.auth.dto.TokenResponse;
import com.example.auth.auth.entity.LoginAttempt;
import com.example.auth.auth.entity.RefreshToken;
import com.example.auth.auth.repository.RefreshTokenRepository;
import com.example.auth.global.error.BusinessException;
import com.example.auth.global.error.ErrorCode;
import com.example.auth.global.security.JwtTokenProvider;
import com.example.auth.support.MutableClock;
import com.example.auth.support.TestRsaKeys;
import com.example.auth.support.TestTokens;
import com.nimbusds.jwt.SignedJWT;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.convention.TestBean;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * sp-docs/plan/phase1.md §4 AU-06·AU-07 의 "검증" 표 중 저장·Claim·회전 쪽과, D-17 의 "검증" 표 중
 * 재사용 유예·로그아웃 대조 쪽을 테스트로 옮긴 것이다. HTTP 상태·응답 본문은 {@link com.example.auth.auth.controller.AuthControllerTest}
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
 *
 * <p>sp-docs/plan/phase2-auth-member.md AU-18 의 검증 표 중 응답과 카운터 값 쪽도 여기 있다(정본은
 * sp-docs/requirements/member.md §12). 트랜잭션 경계·연결과, 다른 연결이 끼어드는 대역이 필요한 행은
 * {@link LoginAttemptServiceTest} 가 본다. 카운터는 {@code JdbcTemplate} 으로 커밋된 값을 읽는다.
 */
@SpringBootTest
@ActiveProfiles("test")
class AuthServiceTest {

	private static final String RAW_PASSWORD = "Passw0rd!";

	/** AU-18 의 테스트가 쓰는 틀린 비밀번호. AU-18 전에 쓴 테스트들은 같은 값을 리터럴로 적는다. */
	private static final String WRONG_PASSWORD = "Other1!pw";

	/**
	 * AU-18 의 테스트가 시계를 맞추는 기준 시각. 한도(5)·잠금(15분)·24시간은 이 시각에 리터럴로 더한다 — 카운터 빈의 상수를
	 * 읽어 기대값을 만들면 상수를 바꾼 변이도 통과한다.
	 */
	private static final LocalDateTime LOCK_NOW = LocalDateTime.of(2026, 11, 13, 10, 0, 0);

	/** V3 seed 의 계정 (sp-docs/requirements/member.md §10.1). 테스트가 만든 것이 아니다. */
	private static final String ADMIN_EMAIL = "admin@example.com";

	/** sp-docs/api-contract.md §6 의 claim 전체. 하나라도 늘거나 줄면 계약이 깨진다. */
	private static final String[] CONTRACT_CLAIMS = {"sub", "role", "iss", "iat", "exp"};

	/** 앱 시계를 바꿔 끼운다. 고정하지 않은 테스트에서는 시스템 시계다 ({@link MutableClock}). */
	private static final MutableClock CLOCK = new MutableClock();

	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	/** 애플리케이션의 {@code Clock} 빈을 {@link #CLOCK} 로 바꾼다 ({@code ClockConfig}). */
	@TestBean
	private Clock clock;

	static Clock clock() {
		return CLOCK;
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

	/** AU-18 — 서비스를 직접 만드는 테스트가 넘긴다. 애플리케이션의 카운터 빈이다. */
	@Autowired
	private LoginAttemptService loginAttemptService;

	/** 서비스를 직접 만드는 테스트가 넘긴다 — 로그인의 Refresh Token 저장 트랜잭션을 연다. 애플리케이션의 빈이다. */
	@Autowired
	private PlatformTransactionManager transactionManager;

	/** AU-18 — 커밋된 {@code login_attempt} 를 영속성 컨텍스트를 거치지 않고 읽고 심는다. 이 스레드에는 트랜잭션이 없다. */
	@Autowired
	private JdbcTemplate jdbcTemplate;

	/** 정리가 지운다 — 다른 클래스가 남긴 행이 계정 삭제를 {@code fk_account_token_account} 에 걸지 않게 한다. */
	@Autowired
	private AccountTokenRepository accountTokenRepository;

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
	 * <p>{@code fk_refresh_token_account} 가 있으므로 토큰을 먼저 지운다. {@code account_token} 도 같은 이유로 먼저 지운다
	 * ({@code fk_account_token_account}).
	 *
	 * <p>AU-18 부터 로그인 실패가 {@code login_attempt} 행을 커밋한다. 그 테이블은 계정을 참조하지 않지만 남기면 같은 이메일을
	 * 쓰는 다음 테스트의 카운터가 이어진다 — 먼저 지운다.
	 */
	@AfterEach
	void 정리() {
		CLOCK.reset();
		this.accountTokenRepository.deleteAllInBatch();
		this.jdbcTemplate.update("delete from login_attempt");
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
				.as("실패는 저장 전에 예외로 끝나므로 아무것도 쓰이지 않는다")
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
		AuthService service = new AuthService(this.accountRepository, this.refreshTokenRepository,
				counting, this.jwtTokenProvider, this.loginAttemptService, this.transactionManager, this.clock);

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

	// --- AU-16 미인증 로그인 차단 (sp-docs/requirements/member.md §3 규칙 11·§12.1 의 5) ---

	@Test
	@DisplayName("미인증 계정은 비밀번호가 맞으면 403 AU006 이고 Refresh Token 을 저장하지 않는다")
	void 미인증_계정의_맞는_비밀번호는_AU006() {
		미인증_계정을_만든다("au16-unverified@example.com");

		BusinessException thrown = 로그인에_실패한다("au16-unverified@example.com", RAW_PASSWORD);

		assertThat(thrown.getErrorCode()).isEqualTo(ErrorCode.EMAIL_NOT_VERIFIED);
		assertThat(thrown.getErrorCode().getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
		assertThat(this.refreshTokenRepository.findAll()).as("토큰을 주지 않는다").isEmpty();
	}

	@Test
	@DisplayName("미인증 계정이어도 비밀번호가 틀리면 401 AU003 이다 — AU006 은 비밀번호가 맞은 뒤에만 나온다")
	void 미인증_계정의_틀린_비밀번호는_AU003() {
		미인증_계정을_만든다("au16-unverified-wrong@example.com");

		BusinessException thrown = 로그인에_실패한다("au16-unverified-wrong@example.com", "Other1!pw");

		assertThat(thrown.getErrorCode()).isEqualTo(ErrorCode.LOGIN_FAILED);
		assertThat(this.refreshTokenRepository.findAll()).isEmpty();
	}

	@Test
	@DisplayName("탈퇴한 미인증 계정은 비밀번호가 맞아도 AU006 이 아니라 401 AU003 이다 — 탈퇴 계정은 없는 계정이다")
	void 탈퇴한_미인증_계정은_AU003() {
		Account account = 미인증_계정을_만든다("au16-unverified-withdrawn@example.com");
		account.withdraw();
		this.accountRepository.saveAndFlush(account);

		BusinessException thrown = 로그인에_실패한다("au16-unverified-withdrawn@example.com", RAW_PASSWORD);

		assertThat(thrown.getErrorCode()).isEqualTo(ErrorCode.LOGIN_FAILED);
		assertThat(this.refreshTokenRepository.findAll()).isEmpty();
	}

	@Test
	@DisplayName("인증을 채운 뒤에는 같은 계정이 로그인된다")
	void 인증한_뒤_로그인된다() {
		Account account = 미인증_계정을_만든다("au16-verified-later@example.com");
		assertThat(로그인에_실패한다("au16-verified-later@example.com", RAW_PASSWORD).getErrorCode())
				.isEqualTo(ErrorCode.EMAIL_NOT_VERIFIED);
		account.markEmailVerified(CLOCK);
		this.accountRepository.saveAndFlush(account);

		TokenResponse tokens = this.authService.login(로그인("au16-verified-later@example.com", RAW_PASSWORD));

		assertThat(tokens.accessToken()).isNotBlank();
		assertThat(this.refreshTokenRepository.findByAccountId(account.getId())).isPresent();
	}

	// --- AU-18 로그인 잠금 (sp-docs/requirements/member.md §12, 갱신 문장은 sp-docs/domain-model.md §2.5) ---

	@Test
	@DisplayName("같은 이메일로 틀린 비밀번호를 연속으로 넣으면 넷째까지 AU003·카운터 1~4, 다섯째는 AU005 이고 15분 잠그며 0 이 된다")
	void 다섯째_실패가_잠근다() {
		String email = "au18-five@example.com";
		계정을_만든다(email);

		for (int i = 1; i <= 4; i++) {
			LocalDateTime at = LOCK_NOW.plusMinutes(i);
			CLOCK.set(at);
			assertThat(로그인에_실패한다(email, WRONG_PASSWORD).getErrorCode())
					.as("%d번째 실패", i).isEqualTo(ErrorCode.LOGIN_FAILED);
			assertThat(카운터(email)).as("%d번째 실패 뒤", i).isEqualTo(new Counter(i, null, at));
		}
		LocalDateTime fifth = LOCK_NOW.plusMinutes(5);
		CLOCK.set(fifth);
		BusinessException thrown = 로그인에_실패한다(email, WRONG_PASSWORD);

		assertThat(thrown.getErrorCode()).isEqualTo(ErrorCode.LOGIN_LOCKED);
		assertThat(thrown.getErrorCode().getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
		assertThat(thrown.getErrorCode().getCode()).isEqualTo("AU005");
		assertThat(카운터(email)).as("다섯째가 15분 잠그고 카운터를 0 으로 한다")
				.isEqualTo(new Counter(0, fifth.plusMinutes(15), fifth));
	}

	/**
	 * 잠긴 동안에는 맞는 비밀번호도 {@code AU005} 이고, 어느 쪽도 세지 않고 잠금을 늘리지 않는다 — 잠긴 동안의 시도가 잠금을
	 * 늘리면 남이 잠금을 끝없이 이어 붙일 수 있다 (sp-docs/security.md §11). 시도는 잠금 직후와 풀리기 1초 전에 한다.
	 */
	@Test
	@DisplayName("잠긴 동안의 시도는 비밀번호와 무관하게 AU005 이고 카운터·locked_until·updated_at 이 그대로다")
	void 잠긴_동안의_시도는_세지_않는다() {
		String email = "au18-locked-attempts@example.com";
		Account account = 계정을_만든다(email);
		잠근다(email, LOCK_NOW);
		Counter locked = new Counter(0, LOCK_NOW.plusMinutes(15), LOCK_NOW);
		assertThat(카운터(email)).as("픽스처 — 잠긴 행").isEqualTo(locked);

		for (LocalDateTime at : List.of(LOCK_NOW.plusMinutes(1), LOCK_NOW.plusMinutes(15).minusSeconds(1))) {
			CLOCK.set(at);
			assertThat(로그인에_실패한다(email, WRONG_PASSWORD).getErrorCode())
					.as("%s 틀린 비밀번호", at).isEqualTo(ErrorCode.LOGIN_LOCKED);
			assertThat(로그인에_실패한다(email, RAW_PASSWORD).getErrorCode())
					.as("%s 맞는 비밀번호", at).isEqualTo(ErrorCode.LOGIN_LOCKED);
			assertThat(카운터(email)).as("%s 의 두 시도 뒤", at).isEqualTo(locked);
		}
		assertThat(this.refreshTokenRepository.findByAccountId(account.getId()))
				.as("맞는 비밀번호도 토큰을 받지 않았다").isEmpty();
	}

	@Test
	@DisplayName("잠금 시각 1초 전에는 맞는 비밀번호도 AU005 이고, 잠금 시각에는 로그인되며 카운터가 0 이 된다")
	void 잠금은_잠금_시각에_풀린다() {
		String email = "au18-unlock@example.com";
		Account account = 계정을_만든다(email);
		잠근다(email, LOCK_NOW);

		CLOCK.set(LOCK_NOW.plusMinutes(15).minusSeconds(1));
		assertThat(로그인에_실패한다(email, RAW_PASSWORD).getErrorCode()).isEqualTo(ErrorCode.LOGIN_LOCKED);

		LocalDateTime unlockedAt = LOCK_NOW.plusMinutes(15);
		CLOCK.set(unlockedAt);
		TokenResponse tokens = this.authService.login(로그인(email, RAW_PASSWORD));

		assertThat(tokens.accessToken()).isNotBlank();
		assertThat(this.refreshTokenRepository.findByAccountId(account.getId())).isPresent();
		assertThat(카운터(email)).isEqualTo(new Counter(0, null, unlockedAt));
	}

	/** 잠그는 문장이 카운터를 0 으로 했으므로 풀린 뒤의 첫 실패는 1 이다 — 그러지 않으면 6 이 되어 곧바로 다시 잠긴다. */
	@Test
	@DisplayName("잠금이 풀린 뒤의 실패는 AU003 이고 1부터 센다")
	void 풀린_뒤의_실패는_1부터_센다() {
		String email = "au18-after-unlock@example.com";
		계정을_만든다(email);
		잠근다(email, LOCK_NOW);

		LocalDateTime after = LOCK_NOW.plusMinutes(15);
		CLOCK.set(after);
		assertThat(로그인에_실패한다(email, WRONG_PASSWORD).getErrorCode()).isEqualTo(ErrorCode.LOGIN_FAILED);

		assertThat(카운터(email))
				.as("1부터 센다. 세는 문장은 잠그지 않는 실패에서 locked_until 을 바꾸지 않아 지난 잠금 시각이 남는다")
				.isEqualTo(new Counter(1, after, after));
	}

	/**
	 * 정본의 조건은 「마지막 실패에서 24시간이 지났으면 1부터」 다 (sp-docs/requirements/member.md §12.2). 갱신 문장은 그것을
	 * {@code updated_at <= :now - 24h} 로 적는다(sp-docs/domain-model.md §2.5) — 정확히 24시간이면 1부터, 1초 모자라면 이어서
	 * 센다. 두 이메일은 계정이 없다 — 없는 이메일도 같은 규칙으로 센다.
	 */
	@Test
	@DisplayName("마지막 실패에서 24시간 뒤의 실패는 1부터 다시 센다 — 1초 모자라면 이어서 센다")
	void 하루가_지난_실패는_1부터_센다() {
		String restarts = "au18-window-restart@example.com";
		String continues = "au18-window-continue@example.com";
		CLOCK.set(LOCK_NOW);
		for (int i = 0; i < 3; i++) {
			로그인에_실패한다(restarts, WRONG_PASSWORD);
			로그인에_실패한다(continues, WRONG_PASSWORD);
		}

		assertThat(카운터(restarts)).as("픽스처").isEqualTo(new Counter(3, null, LOCK_NOW));
		assertThat(카운터(continues)).as("픽스처").isEqualTo(new Counter(3, null, LOCK_NOW));

		LocalDateTime dayLater = LOCK_NOW.plusHours(24);
		CLOCK.set(dayLater.minusSeconds(1));
		assertThat(로그인에_실패한다(continues, WRONG_PASSWORD).getErrorCode()).isEqualTo(ErrorCode.LOGIN_FAILED);
		CLOCK.set(dayLater);
		assertThat(로그인에_실패한다(restarts, WRONG_PASSWORD).getErrorCode()).isEqualTo(ErrorCode.LOGIN_FAILED);

		assertThat(카운터(continues)).isEqualTo(new Counter(4, null, dayLater.minusSeconds(1)));
		assertThat(카운터(restarts)).isEqualTo(new Counter(1, null, dayLater));
	}

	/**
	 * 키는 입력의 ASCII 대문자만 소문자로 바꾼 값이다 (sp-docs/requirements/member.md §12.1). H2 는 데이터를 대소문자를 구분해
	 * 비교하므로 계정을 찾는 표기는 계정과 같은 표기 하나다 — 나머지는 없는 이메일로 센다. 어느 쪽이든 같은 키로 세어야 한다.
	 * 그 밖의 표기(비ASCII 등)를 합치는지는 실 MySQL 측정 대상이다 (sp-docs/plan/phase2-auth-member.md §5.1).
	 */
	@Test
	@DisplayName("ASCII 대소문자만 다른 이메일로 번갈아 실패하면 한 키로 센다 — 다섯째가 AU005 다")
	void 대소문자만_다른_이메일은_한_키로_센다() {
		String email = "au18-case@example.com";
		계정을_만든다(email);
		CLOCK.set(LOCK_NOW);

		for (String spelling : List.of("AU18-Case@Example.com", email, "AU18-CASE@EXAMPLE.COM", "au18-cASE@example.Com")) {
			assertThat(로그인에_실패한다(spelling, WRONG_PASSWORD).getErrorCode())
					.as(spelling).isEqualTo(ErrorCode.LOGIN_FAILED);
		}
		assertThat(키들()).as("키는 하나다").containsExactly(email);
		assertThat(카운터(email)).isEqualTo(new Counter(4, null, LOCK_NOW));

		assertThat(로그인에_실패한다("Au18-Case@EXAMPLE.com", WRONG_PASSWORD).getErrorCode())
				.isEqualTo(ErrorCode.LOGIN_LOCKED);
	}

	/**
	 * 키 변환은 판정·세기·0 으로 하기가 모두 한다. 저장된 표기에 대문자가 든 계정은 그 표기로 계정을 찾고, 키는 소문자다 —
	 * 판정이나 0 으로 하기가 변환을 빠뜨리면 H2 는 데이터를 대소문자를 구분해 비교하므로 그 키의 행을 찾지 못한다. 그러면
	 * 잠긴 계정이 맞는 비밀번호로 로그인되거나, 성공 뒤에도 카운터가 남는다.
	 */
	@Test
	@DisplayName("저장된 표기에 대문자가 든 계정 — 잠기면 그 표기의 맞는 비밀번호도 AU005, 풀린 뒤의 성공은 그 키를 0 으로 한다")
	void 대문자가_든_계정의_판정과_0_으로_하기() {
		String stored = "AU18-Upper@Example.com";
		Account account = 계정을_만든다(stored);
		잠근다(stored, LOCK_NOW);
		assertThat(키들()).containsExactly("au18-upper@example.com");

		CLOCK.set(LOCK_NOW.plusMinutes(1));
		assertThat(로그인에_실패한다(stored, RAW_PASSWORD).getErrorCode()).isEqualTo(ErrorCode.LOGIN_LOCKED);
		assertThat(this.refreshTokenRepository.findByAccountId(account.getId())).isEmpty();

		LocalDateTime unlocked = LOCK_NOW.plusMinutes(15);
		CLOCK.set(unlocked);
		assertThat(로그인에_실패한다(stored, WRONG_PASSWORD).getErrorCode()).isEqualTo(ErrorCode.LOGIN_FAILED);
		assertThat(카운터(stored)).as("픽스처 — 풀린 뒤의 실패 하나").isEqualTo(new Counter(1, unlocked, unlocked));

		LocalDateTime success = unlocked.plusMinutes(1);
		CLOCK.set(success);
		this.authService.login(로그인(stored, RAW_PASSWORD));
		assertThat(카운터(stored)).isEqualTo(new Counter(0, null, success));
	}

	/**
	 * 완료 기준 「키는 AU-12 의 변환이다(ASCII 대문자만)」 의 비ASCII 쪽. 비ASCII 는 바꾸지 않는다 — {@code Locale.ROOT} 의
	 * 소문자 변환은 U+0130 {@code İ} 를 {@code i} + U+0307 로 바꾼다 (sp-docs/requirements/member.md §12.1). 저장된 표기에
	 * ASCII 대문자가 없으므로 키는 그 표기 그대로다 — ASCII 대문자 쪽은 {@link #대문자가_든_계정의_판정과_0_으로_하기()} 가
	 * 본다. 세기·판정·0 으로 하기가 모두 그 키를 쓰는지 본다. 이 표기를 콜레이션이 계정 조회와 같은 키로 합치는지는 실
	 * MySQL 측정 대상이다 (sp-docs/plan/phase2-auth-member.md §5.1).
	 */
	@Test
	@DisplayName("비ASCII 대문자가 든 계정 — 키는 그 글자를 바꾸지 않고, 세기·판정·0 으로 하기가 모두 그 키를 쓴다")
	void 비ASCII_대문자가_든_계정의_키() {
		String stored = "au18-\u0130stanbul@example.com";
		Account account = 계정을_만든다(stored);
		잠근다(stored, LOCK_NOW);
		assertThat(키들()).as("세기의 키 — 입력 그대로").containsExactly("au18-\u0130stanbul@example.com");

		CLOCK.set(LOCK_NOW.plusMinutes(1));
		assertThat(로그인에_실패한다(stored, RAW_PASSWORD).getErrorCode()).as("판정의 키").isEqualTo(ErrorCode.LOGIN_LOCKED);
		assertThat(this.refreshTokenRepository.findByAccountId(account.getId())).isEmpty();

		LocalDateTime success = LOCK_NOW.plusMinutes(15);
		CLOCK.set(success);
		this.authService.login(로그인(stored, RAW_PASSWORD));
		assertThat(카운터(stored)).as("0 으로 하기의 키").isEqualTo(new Counter(0, null, success));
	}

	@Test
	@DisplayName("실패를 쌓아 둔 뒤 성공하면 카운터 0 이 커밋된다")
	void 성공은_카운터를_0_으로_한다() {
		String email = "au18-success-reset@example.com";
		계정을_만든다(email);
		CLOCK.set(LOCK_NOW);
		for (int i = 0; i < 3; i++) {
			로그인에_실패한다(email, WRONG_PASSWORD);
		}
		assertThat(카운터(email)).as("픽스처").isEqualTo(new Counter(3, null, LOCK_NOW));

		LocalDateTime later = LOCK_NOW.plusMinutes(1);
		CLOCK.set(later);
		this.authService.login(로그인(email, RAW_PASSWORD));

		assertThat(카운터(email)).isEqualTo(new Counter(0, null, later));
	}

	/**
	 * {@code AU006} 은 예외로 끝나는 응답이다 — 0 으로 하기가 그 예외로 되돌려지는 트랜잭션 안이면 함께 되돌려져 카운터가 3
	 * 으로 남는다 (sp-docs/requirements/member.md §12.2).
	 */
	@Test
	@DisplayName("실패를 쌓아 둔 뒤 미인증 계정의 맞는 비밀번호는 403 AU006 이고 카운터 0 이 커밋된다")
	void 미인증의_맞는_비밀번호는_카운터를_0_으로_한다() {
		String email = "au18-unverified-reset@example.com";
		미인증_계정을_만든다(email);
		CLOCK.set(LOCK_NOW);
		for (int i = 0; i < 3; i++) {
			로그인에_실패한다(email, WRONG_PASSWORD);
		}
		assertThat(카운터(email)).as("픽스처").isEqualTo(new Counter(3, null, LOCK_NOW));

		LocalDateTime later = LOCK_NOW.plusMinutes(1);
		CLOCK.set(later);
		assertThat(로그인에_실패한다(email, RAW_PASSWORD).getErrorCode()).isEqualTo(ErrorCode.EMAIL_NOT_VERIFIED);

		assertThat(카운터(email)).isEqualTo(new Counter(0, null, later));
	}

	/**
	 * 실패 응답은 예외로 끝난다. 이 스레드에는 트랜잭션이 없어 {@link #카운터} 는 커밋된 값을 읽는다 — 그 예외로 되돌려지는
	 * 트랜잭션에서 셌다면 행이 없다.
	 */
	@Test
	@DisplayName("실패 응답 뒤에 login_attempt 행이 커밋되어 있다 — 응답이 예외로 끝나도 남는다")
	void 실패의_카운트가_커밋되어_있다() {
		String email = "au18-committed@example.com";
		계정을_만든다(email);
		CLOCK.set(LOCK_NOW);

		assertThat(로그인에_실패한다(email, WRONG_PASSWORD).getErrorCode()).isEqualTo(ErrorCode.LOGIN_FAILED);

		assertThat(카운터(email)).isEqualTo(new Counter(1, null, LOCK_NOW));
	}

	/**
	 * 판정 시각은 앱 시계의 값을 초로 자른 것이다 (sp-docs/domain-model.md §2.5). 자르지 않으면 H2 는 소수부를 남기고
	 * MySQL 의 {@code DATETIME} 은 반올림해 두 DB 의 저장값이 갈린다 (§1.1). 시계에 소수부를 주고 증가와 잠금이 쓴 시각을
	 * 본다.
	 */
	@Test
	@DisplayName("시계에 소수부가 있어도 증가와 잠금이 쓰는 시각은 초로 자른 값이다")
	void 판정_시각은_초로_자른_값이다() {
		String email = "au18-truncated-now@example.com";
		CLOCK.set(LOCK_NOW.plusNanos(700_000_000));

		로그인에_실패한다(email, WRONG_PASSWORD);
		로그인에_실패한다(email, WRONG_PASSWORD);
		assertThat(카운터(email)).as("증가").isEqualTo(new Counter(2, null, LOCK_NOW));

		for (int i = 3; i <= 5; i++) {
			로그인에_실패한다(email, WRONG_PASSWORD);
		}
		assertThat(카운터(email)).as("잠금").isEqualTo(new Counter(0, LOCK_NOW.plusMinutes(15), LOCK_NOW));
	}

	/**
	 * 100자는 이메일의 최대 길이(sp-docs/requirements/member.md §2)이자 키 컬럼의 폭이다(§12.1). 100자는 세고 101자는
	 * 세지 않는다.
	 */
	@Test
	@DisplayName("이메일이 100자를 넘으면 AU003 이고 세지 않는다. 100자 이메일은 센다")
	void 백자를_넘는_이메일은_세지_않는다() {
		String hundred = "a".repeat(88) + "@example.com";
		String hundredOne = "a".repeat(89) + "@example.com";
		assertThat(hundred).as("픽스처").hasSize(100);
		assertThat(hundredOne).as("픽스처").hasSize(101);
		CLOCK.set(LOCK_NOW);

		assertThat(로그인에_실패한다(hundredOne, RAW_PASSWORD).getErrorCode()).isEqualTo(ErrorCode.LOGIN_FAILED);
		assertThat(키들()).as("101자는 세지 않는다").isEmpty();

		assertThat(로그인에_실패한다(hundred, RAW_PASSWORD).getErrorCode()).isEqualTo(ErrorCode.LOGIN_FAILED);
		assertThat(카운터(hundred)).as("100자는 센다").isEqualTo(new Counter(1, null, LOCK_NOW));
	}

	@Test
	@DisplayName("이메일 또는 비밀번호가 비면 AU003 이고 세지 않는다 — 있는 이메일 + 빈 비밀번호도 같다")
	void 빈_값은_세지_않는다() {
		String email = "au18-blank@example.com";
		계정을_만든다(email);
		CLOCK.set(LOCK_NOW);

		for (LoginRequest blank : Arrays.asList(
				로그인(null, RAW_PASSWORD), 로그인("", RAW_PASSWORD), 로그인("   ", RAW_PASSWORD),
				로그인(email, null), 로그인(email, ""), 로그인(email, "   "))) {
			assertThatThrownBy(() -> this.authService.login(blank))
					.as("%s", blank)
					.isInstanceOf(BusinessException.class)
					.extracting(e -> ((BusinessException) e).getErrorCode())
					.isEqualTo(ErrorCode.LOGIN_FAILED);
		}

		assertThat(키들()).isEmpty();
	}

	/**
	 * 잠긴 경로도 BCrypt 를 정확히 한 번 한다 — 응답 시간으로 계정의 존재를 드러내지 않는 규칙(sp-docs/security.md §4.1)이
	 * 이 경로에도 적용된다(sp-docs/requirements/member.md §12.1 「잠긴 경로도 BCrypt 를 한 번 한다」). 횟수는
	 * {@link #세_실패_경로가_matches_를_한_번씩_한다} 와 같은 방법으로 센다. 잠긴 행은 SQL 로 심는다.
	 */
	@Test
	@DisplayName("잠긴 경로도 matches 를 정확히 한 번 한다 — 있는 계정의 맞는·틀린 비밀번호, 탈퇴 계정, 없는 이메일")
	void 잠긴_경로가_matches_를_한_번씩_한다() {
		String active = "au18-bcrypt@example.com";
		String withdrawn = "au18-bcrypt-withdrawn@example.com";
		String absent = "au18-bcrypt-none@example.com";
		계정을_만든다(active);
		탈퇴한_계정을_만든다(withdrawn);
		CLOCK.set(LOCK_NOW);
		for (String email : List.of(active, withdrawn, absent)) {
			카운터를_심는다(email, new Counter(0, LOCK_NOW.plusMinutes(10), LOCK_NOW.minusMinutes(5)));
		}
		CountingPasswordEncoder counting = new CountingPasswordEncoder(this.passwordEncoder);
		AuthService service = new AuthService(this.accountRepository, this.refreshTokenRepository,
				counting, this.jwtTokenProvider, this.loginAttemptService, this.transactionManager, this.clock);

		Map<String, LoginRequest> 잠긴_경로 = new LinkedHashMap<>();
		잠긴_경로.put("맞는 비밀번호", 로그인(active, RAW_PASSWORD));
		잠긴_경로.put("틀린 비밀번호", 로그인(active, WRONG_PASSWORD));
		잠긴_경로.put("탈퇴 계정", 로그인(withdrawn, RAW_PASSWORD));
		잠긴_경로.put("없는 이메일", 로그인(absent, RAW_PASSWORD));

		잠긴_경로.forEach((이름, request) -> {
			counting.reset();
			assertThatThrownBy(() -> service.login(request))
					.as(이름)
					.isInstanceOf(BusinessException.class)
					.extracting(e -> ((BusinessException) e).getErrorCode())
					.isEqualTo(ErrorCode.LOGIN_LOCKED);
			assertThat(counting.matchesCalls())
					.as("%s — 0 이면 잠긴 경로가 비교를 건너뛴 것이고 시간으로 드러난다", 이름)
					.isEqualTo(1);
		});
	}

	/**
	 * 판정의 축을 맞세운다 — 계정 상태(활성·미인증·탈퇴·없음) × 비밀번호(맞음·틀림) × 잠금(잠김·안잠김). 기대값은 조합마다
	 * 적는다 (sp-docs/requirements/member.md §12.1, sp-docs/api-contract.md §2.1 의 표).
	 *
	 * <p>잠기지 않은 카운터는 2 로 심는다 — 세면 3, 0 으로 하면 0 이 되어 둘이 갈린다. 잠긴 카운터는 그대로여야 한다. 다른
	 * 이메일의 카운터는 한도 하나 전(4)으로 심는다 — 어느 조합도 그것을 바꾸지 않는다. 기대 카운터의 {@code 그대로} 는 심은
	 * 값이고, 숫자는 그 수와 판정 시각(잠금 없음)이다.
	 */
	@ParameterizedTest(name = "{0} · 비밀번호 {1} · {2} → {3}, 카운터 {4}")
	@CsvSource({
			"활성,   맞음, 안잠김, 성공,  0",
			"활성,   틀림, 안잠김, AU003, 3",
			"미인증, 맞음, 안잠김, AU006, 0",
			"미인증, 틀림, 안잠김, AU003, 3",
			"탈퇴,   맞음, 안잠김, AU003, 3",
			"탈퇴,   틀림, 안잠김, AU003, 3",
			"없음,   맞음, 안잠김, AU003, 3",
			"없음,   틀림, 안잠김, AU003, 3",
			"활성,   맞음, 잠김,   AU005, 그대로",
			"활성,   틀림, 잠김,   AU005, 그대로",
			"미인증, 맞음, 잠김,   AU005, 그대로",
			"미인증, 틀림, 잠김,   AU005, 그대로",
			"탈퇴,   맞음, 잠김,   AU005, 그대로",
			"탈퇴,   틀림, 잠김,   AU005, 그대로",
			"없음,   맞음, 잠김,   AU005, 그대로",
			"없음,   틀림, 잠김,   AU005, 그대로"
	})
	@DisplayName("계정 상태 × 비밀번호 × 잠금의 응답과 카운터 — 다른 이메일의 카운터는 그대로다")
	void 판정의_축(String 상태, String 비밀번호, String 잠금, String 기대_응답, String 기대_카운터) {
		String email = "au18-axis@example.com";
		String other = "au18-axis-other@example.com";
		switch (상태) {
			case "활성" -> 계정을_만든다(email);
			case "미인증" -> 미인증_계정을_만든다(email);
			case "탈퇴" -> 탈퇴한_계정을_만든다(email);
			case "없음" -> { }
			default -> fail("픽스처의 계정 상태: " + 상태);
		}
		Counter 심은_카운터 = "잠김".equals(잠금)
				? new Counter(0, LOCK_NOW.plusMinutes(10), LOCK_NOW.minusMinutes(5))
				: new Counter(2, null, LOCK_NOW.minusMinutes(1));
		Counter 다른_카운터 = new Counter(4, null, LOCK_NOW.minusMinutes(1));
		카운터를_심는다(email, 심은_카운터);
		카운터를_심는다(other, 다른_카운터);
		CLOCK.set(LOCK_NOW);
		LoginRequest request = 로그인(email, "맞음".equals(비밀번호) ? RAW_PASSWORD : WRONG_PASSWORD);

		if ("성공".equals(기대_응답)) {
			assertThat(this.authService.login(request).accessToken()).isNotBlank();
		} else {
			BusinessException thrown = 로그인에_실패한다(email, request.password());
			assertThat(thrown.getErrorCode().getCode()).isEqualTo(기대_응답);
		}

		assertThat(카운터(email)).isEqualTo("그대로".equals(기대_카운터)
				? 심은_카운터
				: new Counter(Integer.parseInt(기대_카운터), null, LOCK_NOW));
		assertThat(카운터(other)).as("다른 이메일").isEqualTo(다른_카운터);
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
	 * 회전이 조건부 UPDATE 이고 0행이면 회전하지 않는다는 것을 서비스 경로에서 본다 — 제시된
	 * 토큰이 저장값과 다르고 유예 안의 직전 토큰도 아니면 거부되어야 한다
	 * (sp-docs/plan/phase1.md §4 AU-07, D-17).
	 *
	 * <p>2026-11-11 D-17 전에는 회전 직후의 옛 토큰을 곧바로 거부했다. 지금은 회전 뒤 10초 동안
	 * 유예가 있으므로(sp-docs/requirements/member.md §6.3) 시계를 유예 밖으로 옮겨서 본다.
	 * {@code RefreshToken.renew()} 로 바꿔 끼우면 이 테스트가 깨진다 — 그 메서드는 조건 없이
	 * 값을 덮으므로 옛 토큰으로도 회전이 성립한다.
	 */
	@Test
	@DisplayName("유예 밖의 직전 Refresh Token 으로 재발급하면 A002 이고 행이 그대로다")
	void 유예_밖의_직전_토큰은_실패한다() {
		Account account = 계정을_만든다("rotated@example.com");
		String 이전_토큰 = 저장된_세션을_만든다(account, 조금_전()).getToken();

		TokenResponse 첫_재발급 = this.authService.reissue(new ReissueRequest(이전_토큰));
		assertThat(첫_재발급.refreshToken()).isNotEqualTo(이전_토큰);
		RefreshToken 회전_뒤 = 행(account);

		CLOCK.set(회전_뒤.getRotatedAt().plusSeconds(11));
		BusinessException thrown = 재발급에_실패한다(이전_토큰);

		assertThat(thrown.getErrorCode()).isEqualTo(ErrorCode.INVALID_TOKEN);
		행이_그대로다(account, 회전_뒤);
	}

	// --- D-17 재사용 유예 (sp-docs/requirements/member.md §6.3, sp-docs/domain-model.md §2.2) ---

	@Test
	@DisplayName("회전은 직전 토큰에 제시된 토큰을, 회전 시각에 앱 시계를 마이크로초로 자른 값을 넣는다")
	void 회전이_직전_토큰과_회전_시각을_쓴다() {
		Account account = 계정을_만든다("rotation-columns@example.com");
		String 제시 = 저장된_세션을_만든다(account, 조금_전()).getToken();
		LocalDateTime 회전_시각 = LocalDateTime.now().withNano(123_456_789);
		CLOCK.set(회전_시각);

		TokenResponse response = this.authService.reissue(new ReissueRequest(제시));

		RefreshToken row = 행(account);
		assertThat(row.getToken()).isEqualTo(response.refreshToken());
		assertThat(row.getPreviousToken()).isEqualTo(제시);
		assertThat(row.getRotatedAt())
				.as("앱 시계의 값을 마이크로초로 자른다 — 반올림하면 실제 회전보다 늦을 수 있다")
				.isEqualTo(회전_시각.withNano(123_456_000));
	}

	@Test
	@DisplayName("회전 직후 직전 토큰으로 재발급하면 새 Access Token 과 지금 저장된 Refresh Token 을 받고 행이 그대로다")
	void 유예_안의_직전_토큰은_지금_저장된_토큰을_받는다() throws Exception {
		Account account = 계정을_만든다("grace@example.com");
		String 직전_토큰 = 저장된_세션을_만든다(account, 조금_전()).getToken();
		TokenResponse 회전 = this.authService.reissue(new ReissueRequest(직전_토큰));
		RefreshToken 회전_뒤 = 행(account);

		TokenResponse 유예 = this.authService.reissue(new ReissueRequest(직전_토큰));

		assertThat(유예.grantType()).isEqualTo("Bearer");
		assertThat(유예.refreshToken())
				.as("다시 회전하지 않고 지금 저장된 값을 그대로 준다")
				.isEqualTo(회전.refreshToken())
				.isEqualTo(회전_뒤.getToken());
		assertThat(SignedJWT.parse(유예.accessToken()).getJWTClaimsSet().getSubject())
				.as("새 Access Token 은 그 계정의 것이다")
				.isEqualTo(String.valueOf(account.getId()));
		assertThat(유예.accessTokenExpiresIn()).isEqualTo(회전.accessTokenExpiresIn());
		행이_그대로다(account, 회전_뒤);
	}

	/**
	 * 10초 경계. 회전 시각을 마이크로초 아래 소수부가 있는 값으로 고정해, 저장값(잘린 값)과 실제
	 * 회전 시각이 다르게 만든다. 판정은 「판정 시각 ≤ 저장된 회전 시각 + 10초」 이고 판정 시각은
	 * 자르지 않는다 (sp-docs/domain-model.md §2.2).
	 */
	@Test
	@DisplayName("판정 시각이 저장된 회전 시각 + 10초면 유예 안이고, 그보다 1나노초 뒤면 A002 다")
	void 유예_경계() {
		Account account = 계정을_만든다("grace-boundary@example.com");
		String 직전_토큰 = 저장된_세션을_만든다(account, 조금_전()).getToken();
		LocalDateTime 회전_시각 = LocalDateTime.now().withNano(700_000_500);
		CLOCK.set(회전_시각);
		TokenResponse 회전 = this.authService.reissue(new ReissueRequest(직전_토큰));
		LocalDateTime 저장된_회전_시각 = 행(account).getRotatedAt();
		assertThat(저장된_회전_시각).isEqualTo(회전_시각.truncatedTo(ChronoUnit.MICROS));

		CLOCK.set(저장된_회전_시각.plusSeconds(10));
		assertThat(this.authService.reissue(new ReissueRequest(직전_토큰)).refreshToken())
				.as("경계 직전(= 저장된 회전 시각 + 10초)은 유예 안이다")
				.isEqualTo(회전.refreshToken());

		CLOCK.set(저장된_회전_시각.plusSeconds(10).plusNanos(1));
		assertThat(재발급에_실패한다(직전_토큰).getErrorCode())
				.as("경계 직후는 유예 밖이다")
				.isEqualTo(ErrorCode.INVALID_TOKEN);
	}

	@Test
	@DisplayName("유예 응답은 창을 밀지 않는다 — 첫 회전 시각 기준으로 유예 밖이면 A002")
	void 유예_응답은_창을_밀지_않는다() {
		Account account = 계정을_만든다("grace-window@example.com");
		String 직전_토큰 = 저장된_세션을_만든다(account, 조금_전()).getToken();
		CLOCK.set(LocalDateTime.now());
		this.authService.reissue(new ReissueRequest(직전_토큰));
		RefreshToken 회전_뒤 = 행(account);

		CLOCK.set(회전_뒤.getRotatedAt().plusSeconds(8));
		this.authService.reissue(new ReissueRequest(직전_토큰));
		행이_그대로다(account, 회전_뒤);

		// 유예 응답 기준으로는 5초 뒤지만 첫 회전 기준으로는 13초 뒤다
		CLOCK.set(회전_뒤.getRotatedAt().plusSeconds(13));
		assertThat(재발급에_실패한다(직전_토큰).getErrorCode()).isEqualTo(ErrorCode.INVALID_TOKEN);
	}

	@Test
	@DisplayName("10초 안에 회전이 두 번 일어나면 처음 토큰은 A002 다 — 직전 토큰은 하나뿐이다")
	void 회전_두_번_뒤_처음_토큰은_실패한다() {
		Account account = 계정을_만든다("grace-twice@example.com");
		String 처음_토큰 = 저장된_세션을_만든다(account, 조금_전()).getToken();
		String 둘째_토큰 = this.authService.reissue(new ReissueRequest(처음_토큰)).refreshToken();
		this.authService.reissue(new ReissueRequest(둘째_토큰));
		RefreshToken 두_번_뒤 = 행(account);
		assertThat(두_번_뒤.getPreviousToken()).isEqualTo(둘째_토큰);

		assertThat(재발급에_실패한다(처음_토큰).getErrorCode()).isEqualTo(ErrorCode.INVALID_TOKEN);
		행이_그대로다(account, 두_번_뒤);
	}

	@Test
	@DisplayName("회전 뒤 다시 로그인하면 옛 세션의 직전 토큰은 A002 다 — 로그인이 직전 토큰을 비웠다")
	void 로그인이_직전_토큰을_비운다() {
		Account account = 계정을_만든다("grace-relogin@example.com");
		String 직전_토큰 = 저장된_세션을_만든다(account, 조금_전()).getToken();
		this.authService.reissue(new ReissueRequest(직전_토큰));

		TokenResponse 새_로그인 = this.authService.login(로그인("grace-relogin@example.com", RAW_PASSWORD));

		RefreshToken row = 행(account);
		assertThat(row.getToken()).isEqualTo(새_로그인.refreshToken());
		assertThat(row.getPreviousToken()).isNull();
		assertThat(row.getRotatedAt()).isNull();
		assertThat(재발급에_실패한다(직전_토큰).getErrorCode()).isEqualTo(ErrorCode.INVALID_TOKEN);
		행이_그대로다(account, row);
	}

	/**
	 * 탈퇴 1단계가 남기는 상태(계정 {@code deleted} + 행 삭제)를 두 단계로 만들어, 유예 경로에서도
	 * 두 방어선이 각각 작동하는지 본다 — 계정 활성 검사와, 최신 커밋 값에 행이 없으면 유예도
	 * 없다는 것 (sp-docs/requirements/member.md §6.3).
	 */
	@Test
	@DisplayName("회전 뒤 계정이 탈퇴하면 유예 안의 직전 토큰도 A002 이고 행이 되살아나지 않는다")
	void 탈퇴_뒤_직전_토큰은_실패한다() {
		Account account = 계정을_만든다("grace-withdrawn@example.com");
		String 직전_토큰 = 저장된_세션을_만든다(account, 조금_전()).getToken();
		this.authService.reissue(new ReissueRequest(직전_토큰));
		RefreshToken 회전_뒤 = 행(account);

		account.withdraw();
		this.accountRepository.saveAndFlush(account);
		assertThat(재발급에_실패한다(직전_토큰).getErrorCode())
				.as("행이 남아 있어도 계정 활성 검사가 유예 경로를 막는다")
				.isEqualTo(ErrorCode.INVALID_TOKEN);
		행이_그대로다(account, 회전_뒤);

		this.refreshTokenRepository.deleteAll();
		this.refreshTokenRepository.flush();
		assertThat(재발급에_실패한다(직전_토큰).getErrorCode()).isEqualTo(ErrorCode.INVALID_TOKEN);
		assertThat(this.refreshTokenRepository.findAll())
				.as("되살아나면 탈퇴 계정에 14일짜리 RefreshToken 이 생긴다")
				.isEmpty();
	}

	/**
	 * 같은 토큰으로 겹친 재발급 두 건. <b>H2 에서 돈다 — 이것만으로 판정하지 않는다</b>
	 * (sp-docs/requirements/member.md §6.3). 실 MySQL 쪽은 로컬 기동으로 따로 본다.
	 *
	 * <p><b>어느 쪽이 회전하고 어느 쪽이 유예인지 단언하지 않는다.</b> 같은 초에 발급하면 새 토큰이
	 * 제시 토큰과 같을 수 있고(§6.2) 실행 순서도 정할 수 없다. 결과로 단언한다 — 둘 다 성공하고,
	 * 받은 Refresh Token 이 같고, 그것이 저장값이다.
	 */
	@Test
	@DisplayName("같은 토큰으로 동시에 보낸 재발급 두 건이 둘 다 성공하고 같은 저장값을 받는다")
	void 동시_재발급은_둘_다_성공한다() throws Exception {
		Account account = 계정을_만든다("grace-concurrent@example.com");
		String 제시 = 저장된_세션을_만든다(account, 조금_전()).getToken();
		CountDownLatch 출발 = new CountDownLatch(1);
		ExecutorService pool = Executors.newFixedThreadPool(2);
		try {
			Future<TokenResponse> 첫째 = pool.submit(() -> {
				출발.await();
				return this.authService.reissue(new ReissueRequest(제시));
			});
			Future<TokenResponse> 둘째 = pool.submit(() -> {
				출발.await();
				return this.authService.reissue(new ReissueRequest(제시));
			});
			출발.countDown();

			String 첫째_토큰 = 첫째.get(30, TimeUnit.SECONDS).refreshToken();
			String 둘째_토큰 = 둘째.get(30, TimeUnit.SECONDS).refreshToken();

			assertThat(첫째_토큰).isEqualTo(둘째_토큰).isEqualTo(행(account).getToken());
		} finally {
			pool.shutdownNow();
		}
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
	 * <p>로그인의 저장은 계정을 잠금 읽기로 다시 읽어 그때 탈퇴한 계정이면 저장하지 않는다
	 * ({@code AuthService#storeRefreshToken}). 이 검사는 그것에 기대지 않는다 — 탈퇴 계정에 행이 남아도 이 검사가 있는 한
	 * 그 행으로 재발급받을 수 없다 (sp-docs/plan/phase1.md §4 AU-07).
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

	// --- 로그아웃 (sp-docs/requirements/member.md §6.4). HTTP 쪽은 AuthControllerTest 가 본다 ---

	@Test
	@DisplayName("로그아웃은 제시한 토큰이 저장된 토큰이면 행을 지우고, 다시 불러도 그대로 끝난다")
	void 로그아웃은_저장된_토큰의_행을_지운다() {
		Account account = 계정을_만든다("logout@example.com");
		String 토큰 = 저장된_세션을_만든다(account, 조금_전()).getToken();

		this.authService.logout(account.getId(), new LogoutRequest(토큰));

		assertThat(this.refreshTokenRepository.findAll()).isEmpty();

		// 이미 지워진 뒤에 다시 불러도 예외가 아니다 — 지울 것이 없을 뿐이다
		this.authService.logout(account.getId(), new LogoutRequest(토큰));
		assertThat(this.refreshTokenRepository.findAll()).isEmpty();
	}

	@Test
	@DisplayName("로그아웃은 제시한 토큰이 직전 토큰이면 유예 밖이어도 행을 지운다")
	void 로그아웃은_직전_토큰의_행도_지운다() {
		Account account = 계정을_만든다("logout-previous@example.com");
		String 직전_토큰 = 저장된_세션을_만든다(account, 조금_전()).getToken();
		this.authService.reissue(new ReissueRequest(직전_토큰));
		CLOCK.set(행(account).getRotatedAt().plusMinutes(5));

		this.authService.logout(account.getId(), new LogoutRequest(직전_토큰));

		assertThat(this.refreshTokenRepository.findAll())
				.as("previous_token 일치에는 시간 제한이 없다 (§6.4)")
				.isEmpty();
	}

	@Test
	@DisplayName("로그아웃 후 같은 Refresh Token 으로 재발급하면 실패한다")
	void 로그아웃_후_재발급은_실패한다() {
		Account account = 계정을_만든다("logout-reissue@example.com");
		String 토큰 = 저장된_세션을_만든다(account, 조금_전()).getToken();

		this.authService.logout(account.getId(), new LogoutRequest(토큰));

		assertThat(재발급에_실패한다(토큰).getErrorCode()).isEqualTo(ErrorCode.INVALID_TOKEN);
		assertThat(this.refreshTokenRepository.findAll())
				.as("거부된 재발급이 행을 다시 만들지 않는다")
				.isEmpty();
	}

	/** 계정당 1행이다 (sp-docs/domain-model.md §2.2). 매번 DB 에서 다시 읽는다. */
	private RefreshToken 행(Account account) {
		return this.refreshTokenRepository.findByAccountId(account.getId()).orElseThrow();
	}

	/** 거부·유예 응답이 행의 값(토큰·만료·직전 토큰·회전 시각)을 바꾸지 않았는가. */
	private void 행이_그대로다(Account account, RefreshToken 전) {
		RefreshToken 후 = 행(account);
		assertThat(후.getId()).isEqualTo(전.getId());
		assertThat(후.getToken()).isEqualTo(전.getToken());
		assertThat(후.getExpiresAt()).isEqualTo(전.getExpiresAt());
		assertThat(후.getPreviousToken()).isEqualTo(전.getPreviousToken());
		assertThat(후.getRotatedAt()).isEqualTo(전.getRotatedAt());
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

	/**
	 * 인증된 계정. 프로필은 만들지 않는다 — auth 는 프로필을 소유하지 않는다.
	 *
	 * <p><b>AU-16 부터 인증을 채운다.</b> 미인증 계정의 맞는 비밀번호는 403 {@code AU006} 이므로
	 * (sp-docs/requirements/member.md §3 규칙 11) 로그인을 선행 상태로 쓰는 테스트들의 계정은 인증돼 있어야 한다.
	 * 미인증은 {@link #미인증_계정을_만든다} 가 만든다.
	 */
	private Account 계정을_만든다(String email) {
		Account account = 미인증_계정을_만든다(email);
		account.markEmailVerified(CLOCK);
		return this.accountRepository.saveAndFlush(account);
	}

	/** {@code email_verified_at} 이 NULL 인 계정 — AU-16 뒤에 가입한 계정이 인증 전에 그렇다. */
	private Account 미인증_계정을_만든다(String email) {
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

	/**
	 * AU-18 — 실제 경로로 잠근다. {@code at} 에 틀린 비밀번호로 다섯 번 실패하고, 넷째까지 {@code AU003}·다섯째가
	 * {@code AU005} 인지 본다. 잠긴 행의 값은 부른 쪽이 본다.
	 */
	private void 잠근다(String email, LocalDateTime at) {
		CLOCK.set(at);
		for (int i = 1; i <= 5; i++) {
			assertThat(로그인에_실패한다(email, WRONG_PASSWORD).getErrorCode())
					.as("잠그는 %d번째 실패", i)
					.isEqualTo((i < 5) ? ErrorCode.LOGIN_FAILED : ErrorCode.LOGIN_LOCKED);
		}
	}

	/** AU-18 — 그 이메일의 {@code login_attempt} 행을 SQL 로 심는다. 키는 AU-12 의 변환으로 만든다. */
	private void 카운터를_심는다(String email, Counter counter) {
		this.jdbcTemplate.update(
				"insert into login_attempt (email_key, failed_count, locked_until, updated_at) values (?, ?, ?, ?)",
				LoginAttempt.emailKeyOf(email), counter.failedCount(), counter.lockedUntil(), counter.updatedAt());
	}

	/** AU-18 — 그 이메일의 커밋된 {@code login_attempt} 행. 행이 없으면 실패한다. JPA 를 거치지 않는다. */
	private Counter 카운터(String email) {
		List<Counter> rows = this.jdbcTemplate.query(
				"select failed_count, locked_until, updated_at from login_attempt where email_key = ?",
				(rs, rowNum) -> new Counter(rs.getInt("failed_count"),
						rs.getObject("locked_until", LocalDateTime.class),
						rs.getObject("updated_at", LocalDateTime.class)),
				LoginAttempt.emailKeyOf(email));
		assertThat(rows).as("%s 의 login_attempt 행", email).hasSize(1);
		return rows.get(0);
	}

	/** AU-18 — 커밋된 {@code login_attempt} 의 키 전부. */
	private List<String> 키들() {
		return this.jdbcTemplate.queryForList("select email_key from login_attempt order by email_key", String.class);
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

	/** AU-18 — {@code login_attempt} 의 연속 실패 수·잠금 시각·마지막 갱신 시각. */
	private record Counter(int failedCount, LocalDateTime lockedUntil, LocalDateTime updatedAt) {
	}

}
