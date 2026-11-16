package com.example.auth.account.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import com.example.auth.account.dto.AccountCreateRequest;
import com.example.auth.account.dto.AccountResponse;
import com.example.auth.account.dto.PasswordChangeRequest;
import com.example.auth.account.dto.WithdrawRequest;
import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.AccountToken;
import com.example.auth.account.entity.Role;
import com.example.auth.account.entity.TokenPurpose;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.account.repository.AccountTokenRepository;
import com.example.auth.account.support.AccountReader;
import com.example.auth.account.support.AccountTokens;
import com.example.auth.auth.entity.RefreshToken;
import com.example.auth.auth.repository.RefreshTokenRepository;
import com.example.auth.global.error.BusinessException;
import com.example.auth.global.error.ErrorCode;
import com.example.auth.global.config.MailExecutorConfig;
import com.example.auth.global.security.JwtTokenProvider;
import com.example.auth.support.MailExecutorDrain;
import com.example.auth.support.RecordingStatementInspector;
import com.example.auth.support.TestRsaKeys;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * sp-docs/plan/phase1.md §4 AU-05·AU-08 의 "검증" 표 중 저장 쪽을 테스트로 옮긴 것이다.
 * HTTP 상태·응답 본문은 {@link com.example.auth.account.controller.AccountControllerTest} 가 본다.
 *
 * <p>실제 {@code PasswordEncoder}(BCrypt strength 10) 와 H2 를 함께 쓴다. 해싱을 스텁으로
 * 바꾸면 "평문이 저장되지 않는다"가 검증되지 않는다.
 */
@SpringBootTest
@ActiveProfiles("test")
class AccountServiceTest {

	private static final String RAW_PASSWORD = "Passw0rd!";

	/** AU-08. sp-docs/api-contract.md §2.2 의 예시 본문이 쓰는 값이다. */
	private static final String NEW_PASSWORD = "NewPassw0rd!";

	/** V3 seed 의 계정 (sp-docs/requirements/member.md §10.1). 테스트가 만든 것이 아니다. */
	private static final String ADMIN_EMAIL = "admin@example.com";

	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	@Autowired
	private AccountService accountService;

	@Autowired
	private AccountRepository accountRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	/** AU-08 — 비밀번호 변경이 지우는 대상 (sp-docs/requirements/member.md §3 규칙 4). */
	@Autowired
	private RefreshTokenRepository refreshTokenRepository;

	/** AU-05 가 쓰는 "없으면 {@code AU001}" 지점. AU-08 의 스텁 생성자에 넘긴다. */
	@Autowired
	private AccountReader accountReader;

	/** Refresh Token 픽스처를 실제 발급 경로로 만들기 위해서다 (sp-docs/conventions.md §9.2). */
	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	/** AU-16 — 스텁 생성자에 넘긴다. 중복 경로는 발급까지 가지 않는다. */
	@Autowired
	private AccountTokenIssuer accountTokenIssuer;

	/** AU-16 — 인증 링크 토큰. 확인이 사용 처리하는 행이고, 가입이 커밋 뒤에 만드는 행이다. */
	@Autowired
	private AccountTokenRepository accountTokenRepository;

	/** AU-16 — 앱 시계. 이 클래스는 바꿔 끼우지 않는다(시스템 시계). 토큰 픽스처의 발급 시각을 정한다. */
	@Autowired
	private Clock clock;

	/** AU-16 — 바깥 트랜잭션을 열고, 커밋된 행을 영속성 컨텍스트를 거치지 않고 읽는다. */
	@Autowired
	private PlatformTransactionManager transactionManager;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	/** AU-16 — 가입이 커밋 뒤에 넘긴 발급 작업이 도는 곳. 정리가 그 작업이 끝나기를 기다린다. */
	@Autowired
	@Qualifier(MailExecutorConfig.MAIL_EXECUTOR)
	private ThreadPoolTaskExecutor mailExecutor;

	/**
	 * <b>seed 행은 남긴다.</b> H2 는 테스트 클래스 사이에 공유되므로
	 * ({@code DB_CLOSE_DELAY=-1}, sp-docs/tech-stack.md §5.3) 여기서 지우면
	 * {@code AdminSeedTest} 가 자기와 무관한 이유로 깨진다.
	 *
	 * <p>{@code fk_refresh_token_account} 가 있으므로 토큰을 먼저 지운다 — AU-08 의 테스트가
	 * {@code refresh_token} 행을 만든다.
	 *
	 * <p><b>AU-16 부터 가입이 다른 스레드에서 {@code account_token} 행을 만든다.</b> 그 작업이 끝나기를 먼저
	 * 기다리고({@link MailExecutorDrain}) 그 행을 지운다 — 남기면 계정 삭제가 {@code fk_account_token_account} 에
	 * 걸린다.
	 */
	@AfterEach
	void 정리() {
		MailExecutorDrain.drain(this.mailExecutor);
		this.accountTokenRepository.deleteAllInBatch();
		this.refreshTokenRepository.deleteAll();
		this.refreshTokenRepository.flush();
		this.accountRepository.deleteAll(this.accountRepository.findAll().stream()
				.filter(account -> !ADMIN_EMAIL.equals(account.getEmail()))
				.toList());
	}

	@Test
	@DisplayName("계정을 생성하면 DB 에 저장되고 응답이 그 행을 가리킨다")
	void 정상_생성() {
		AccountResponse response =
				this.accountService.create(new AccountCreateRequest("user@example.com", RAW_PASSWORD));

		assertThat(response.accountId()).isNotNull();
		assertThat(response.email()).isEqualTo("user@example.com");

		Account saved = this.accountRepository.findById(response.accountId()).orElseThrow();
		assertThat(saved.getEmail()).isEqualTo("user@example.com");
		// 권한은 기본값 USER 다. ADMIN 은 seed 로만 들어간다 (sp-docs/requirements/member.md §10)
		assertThat(saved.getRole()).isEqualTo(Role.USER);
		assertThat(saved.isDeleted()).isFalse();
		assertThat(saved.getCreatedAt()).isNotNull();
	}

	@Test
	@DisplayName("저장된 비밀번호는 평문과 다르고 BCrypt 로 검증된다")
	void 비밀번호가_해싱되어_저장된다() {
		AccountResponse response =
				this.accountService.create(new AccountCreateRequest("hash@example.com", RAW_PASSWORD));

		String stored = this.accountRepository.findById(response.accountId()).orElseThrow().getPassword();

		assertThat(stored).isNotEqualTo(RAW_PASSWORD);
		assertThat(stored).startsWith("$2");
		assertThat(this.passwordEncoder.matches(RAW_PASSWORD, stored)).isTrue();
		assertThat(this.passwordEncoder.matches("other" + RAW_PASSWORD, stored)).isFalse();
	}

	@Test
	@DisplayName("이미 쓰이는 이메일로 생성하면 AU002 다")
	void 중복_이메일() {
		this.accountService.create(new AccountCreateRequest("dup@example.com", RAW_PASSWORD));

		assertThatThrownBy(() ->
				this.accountService.create(new AccountCreateRequest("dup@example.com", RAW_PASSWORD)))
				.isInstanceOf(BusinessException.class)
				.extracting(e -> ((BusinessException) e).getErrorCode())
				.isEqualTo(ErrorCode.EMAIL_DUPLICATED);

		assertThat(테스트가_만든_계정_수()).isEqualTo(1);
	}

	@Test
	@DisplayName("탈퇴한 계정의 이메일로 재가입하면 AU002 다")
	void 탈퇴_계정의_이메일로_재가입() {
		Long id = this.accountService
				.create(new AccountCreateRequest("bye@example.com", RAW_PASSWORD)).accountId();
		Account account = this.accountRepository.findById(id).orElseThrow();
		account.withdraw();
		this.accountRepository.saveAndFlush(account);

		assertThatThrownBy(() ->
				this.accountService.create(new AccountCreateRequest("bye@example.com", RAW_PASSWORD)))
				.as("행이 남고 uk_account_email 이 UNIQUE 다 (sp-docs/requirements/member.md §3 규칙 1)")
				.isInstanceOf(BusinessException.class)
				.extracting(e -> ((BusinessException) e).getErrorCode())
				.isEqualTo(ErrorCode.EMAIL_DUPLICATED);

		// 탈퇴 상태가 되살아나지 않는다
		assertThat(this.accountRepository.findById(id).orElseThrow().isDeleted()).isTrue();
		assertThat(테스트가_만든_계정_수()).isEqualTo(1);
	}

	@Test
	@DisplayName("checkEmail 은 쓸 수 있으면 true, 쓰이고 있으면(탈퇴 포함) false 다")
	void 이메일_중복_확인() {
		assertThat(this.accountService.checkEmail("free@example.com").available()).isTrue();

		this.accountService.create(new AccountCreateRequest("taken@example.com", RAW_PASSWORD));
		assertThat(this.accountService.checkEmail("taken@example.com").available()).isFalse();

		Long id = this.accountService
				.create(new AccountCreateRequest("gone@example.com", RAW_PASSWORD)).accountId();
		Account withdrawn = this.accountRepository.findById(id).orElseThrow();
		withdrawn.withdraw();
		this.accountRepository.saveAndFlush(withdrawn);

		assertThat(this.accountService.checkEmail("gone@example.com").available())
				.as("행이 남고 UNIQUE 가 재사용을 막는다 (sp-docs/api-contract.md §2.3)")
				.isFalse();
	}

	/**
	 * 사전 검사와 INSERT 사이의 경합. {@code uk_account_email} 위반이 그대로 올라가면
	 * {@code GlobalExceptionHandler} 의 마지막 그물에 걸려 <b>500 {@code C005}</b> 가 된다.
	 * 경합은 실제로 재현할 수 없으므로 리포지터리를 스텁으로 두고 그 경로만 좁게 본다.
	 */
	@Test
	@DisplayName("UNIQUE 제약 위반이 500 으로 새지 않고 AU002 가 된다")
	void uk_제약_위반도_AU002() {
		AccountRepository stub = mock(AccountRepository.class);
		given(stub.existsByEmail(anyString())).willReturn(false);
		given(stub.saveAndFlush(any(Account.class)))
				.willThrow(new DataIntegrityViolationException("uk_account_email"));
		// 나머지 협력자는 실제 빈이다. create 경로가 쓰지 않으므로 스텁할 것이 없다
		AccountService service = new AccountService(
				stub, this.passwordEncoder, this.accountReader, this.refreshTokenRepository,
				this.accountTokenIssuer, this.accountTokenRepository, this.clock);

		assertThatThrownBy(() ->
				service.create(new AccountCreateRequest("race@example.com", RAW_PASSWORD)))
				.isInstanceOf(BusinessException.class)
				.extracting(e -> ((BusinessException) e).getErrorCode())
				.isEqualTo(ErrorCode.EMAIL_DUPLICATED);
	}

	/**
	 * <b>{@code security.md} §1 의 strength 10 을 고정한다.</b> {@code SecurityConfigTest} 는
	 * 인스턴스 타입만 보므로, 누가 strength 를 바꿔도 지금은 아무 테스트도 깨지지 않는다.
	 *
	 * <p>이것은 커밋된 픽스처의 모양을 되읽는 순환이 아니다 — <b>런타임에 인코더가 만든 값</b>을
	 * 본다 (sp-docs/requirements/member.md §10.2). BCrypt 해시의 cost 는 접두어에 들어 있다.
	 *
	 * <p>패턴은 문자 클래스로 조립한다. 리터럴로 적으면 {@code AdminSeedTest} 의 저장소 전문
	 * 검색이 이 파일을 잡는다.
	 */
	@Test
	@DisplayName("애플리케이션 PasswordEncoder 빈이 만든 해시가 strength 10 BCrypt 다")
	void 인코더가_strength_10_해시를_만든다() {
		String encoded = this.passwordEncoder.encode(RAW_PASSWORD);

		assertThat(Pattern.compile("^\\$2[aby]\\$10\\$").matcher(encoded).find())
				.as("strength 가 바뀌면 접두어의 cost 가 달라진다 (sp-docs/security.md §1)")
				.isTrue();
		assertThat(encoded).hasSize(60);
	}

	// --- AU-08 비밀번호 변경 (sp-docs/plan/phase1.md §4 AU-08) ---

	@Test
	@DisplayName("비밀번호를 바꾸면 새 해시가 저장되고 refresh_token 행이 사라진다")
	void 정상_변경() {
		Long id = 계정을_만든다("change@example.com");
		String before = 저장된_해시(id);
		refresh_token_행을_만든다(id);

		this.accountService.changePassword(id, new PasswordChangeRequest(RAW_PASSWORD, NEW_PASSWORD));

		String stored = 저장된_해시(id);
		assertThat(stored).isNotEqualTo(before).isNotEqualTo(NEW_PASSWORD).startsWith("$2");
		assertThat(this.passwordEncoder.matches(NEW_PASSWORD, stored))
				.as("새 비밀번호가 BCrypt 로 해싱되어 저장된다 (Account.changePassword)")
				.isTrue();
		assertThat(this.passwordEncoder.matches(RAW_PASSWORD, stored))
				.as("옛 비밀번호로는 더 이상 검증되지 않는다")
				.isFalse();
		assertThat(this.refreshTokenRepository.findByAccountId(id))
				.as("비밀번호 변경 시 Refresh Token 을 삭제한다 "
						+ "(sp-docs/requirements/member.md §3 규칙 4)")
				.isEmpty();
	}

	@Test
	@DisplayName("현재 비밀번호가 틀리면 AU004 이고 비밀번호·토큰이 그대로다")
	void 현재_비밀번호_불일치() {
		Long id = 계정을_만든다("mismatch@example.com");
		String before = 저장된_해시(id);
		refresh_token_행을_만든다(id);

		assertThatThrownBy(() -> this.accountService
				.changePassword(id, new PasswordChangeRequest("Other1!pw", NEW_PASSWORD)))
				.isInstanceOf(BusinessException.class)
				.extracting(e -> ((BusinessException) e).getErrorCode())
				.isEqualTo(ErrorCode.PASSWORD_MISMATCH);

		assertThat(저장된_해시(id)).isEqualTo(before);
		assertThat(this.refreshTokenRepository.findByAccountId(id))
				.as("거부된 변경은 아무것도 지우지 않는다")
				.isPresent();
	}

	/**
	 * <b>형식으로 가르지 않는다</b> (sp-docs/api-contract.md §2.2,
	 * sp-docs/plan/phase1.md §4 AU-08 검증표). 입력은 모두 비밀번호 규칙(§2)을 위반하면서
	 * 값도 틀리다 — {@code C001} 이 아니라 {@code AU004} 로 끝나야 한다.
	 *
	 * <p><b>{@code null}·빈 값·공백만은 여기에 없다. 그것들은 {@code AU004} 가 아니다.</b>
	 * §2.2 의 표가 "누락 · {@code null} · 빈 문자열"을 400 {@code C001} 로 못박았고, 이유는
	 * {@code AU004} 의 메시지("현재 비밀번호가 일치하지 않습니다")가 <b>아무것도 보내지 않은
	 * 요청에는 거짓</b>이라는 것이다. 그 매핑은 {@code PasswordChangeRequest} 의
	 * {@code @NotBlank} 가 컨트롤러 앞에서 처리하고
	 * {@code AccountControllerTest.currentPassword_누락} 이 네 입력으로 고정한다.
	 *
	 * <p>{@code null} 에 {@code BCryptPasswordEncoder.matches} 가
	 * {@code IllegalArgumentException} 을 던지는 것은 막지 않는다. 그 경로로 들어오는 호출자가
	 * 이 저장소에 없고, 생기면 그것은 업무 오류가 아니라 프로그래밍 오류다.
	 */
	@ParameterizedTest(name = "currentPassword = \"{0}\"")
	@ValueSource(strings = {
			"short",      // 8자 미만, 숫자·특수문자 없음
			"비밀번호1234"  // 허용 집합 밖의 문자
	})
	@DisplayName("currentPassword 가 형식 위반이고 값도 틀리면 AU004 다")
	void currentPassword_는_형식으로_가르지_않는다(String currentPassword) {
		Long id = 계정을_만든다("format@example.com");
		String before = 저장된_해시(id);

		assertThatThrownBy(() -> this.accountService
				.changePassword(id, new PasswordChangeRequest(currentPassword, NEW_PASSWORD)))
				.isInstanceOf(BusinessException.class)
				.extracting(e -> ((BusinessException) e).getErrorCode())
				.isEqualTo(ErrorCode.PASSWORD_MISMATCH);

		assertThat(저장된_해시(id)).isEqualTo(before);
	}

	/**
	 * <b>새 비밀번호가 현재와 같아도 거부하지 않는다</b> (sp-docs/api-contract.md §2.2).
	 * 비교에 BCrypt 가 한 번 더 들고, 같은 값으로 바꾸는 것이 해롭지 않다 — RefreshToken 은
	 * 어차피 삭제되어 세션이 끊긴다.
	 *
	 * <p>저장된 해시는 그래도 달라진다. salt 가 새로 뽑히기 때문이다.
	 */
	@Test
	@DisplayName("새 비밀번호가 현재와 같아도 거부하지 않고 토큰을 지운다")
	void 현재와_같은_새_비밀번호() {
		Long id = 계정을_만든다("same@example.com");
		String before = 저장된_해시(id);
		refresh_token_행을_만든다(id);

		this.accountService.changePassword(id, new PasswordChangeRequest(RAW_PASSWORD, RAW_PASSWORD));

		String stored = 저장된_해시(id);
		assertThat(this.passwordEncoder.matches(RAW_PASSWORD, stored)).isTrue();
		assertThat(stored).as("salt 가 새로 뽑히므로 해시 자체는 달라진다").isNotEqualTo(before);
		assertThat(this.refreshTokenRepository.findByAccountId(id)).isEmpty();
	}

	/**
	 * 토큰의 {@code sub} 가 가리키는 계정이 없는 경우다. 조용히 통과시키지 않고 {@code AU001}
	 * 로 끝낸다 ({@code AccountReader}, sp-docs/api-contract.md §8.4).
	 */
	@Test
	@DisplayName("없는 계정의 비밀번호 변경은 AU001 이다")
	void 없는_계정() {
		assertThatThrownBy(() -> this.accountService
				.changePassword(999_999L, new PasswordChangeRequest(RAW_PASSWORD, NEW_PASSWORD)))
				.isInstanceOf(BusinessException.class)
				.extracting(e -> ((BusinessException) e).getErrorCode())
				.isEqualTo(ErrorCode.ACCOUNT_NOT_FOUND);
	}

	/**
	 * <b>탈퇴한 계정은 없는 계정과 같이 {@code AU001} 이다</b> (sp-docs/api-contract.md §2.2).
	 * 행은 존재하므로 {@code AccountReader} 는 통과한다 — 거부는 {@code changePassword} 안에
	 * 있어야 한다. {@code AccountReader} 에 넣으면 {@code DELETE /accounts/me} 의 멱등성이 깨진다.
	 *
	 * <p><b>비밀번호가 맞아도 거부한다.</b> 검사가 비교보다 먼저이므로 닫힌 행에 쓰기가 닿지
	 * 않는다. HTTP 쪽(404 와 {@code updated_at} 불변)은
	 * {@code AccountControllerTest.탈퇴한_계정} 이 본다.
	 */
	@Test
	@DisplayName("탈퇴한 계정의 비밀번호 변경은 AU001 이고 토큰도 지우지 않는다")
	void 탈퇴한_계정() {
		Long id = 계정을_만든다("withdrawn@example.com");
		String before = 저장된_해시(id);
		refresh_token_행을_만든다(id);
		탈퇴시킨다(id);

		assertThatThrownBy(() -> this.accountService
				.changePassword(id, new PasswordChangeRequest(RAW_PASSWORD, NEW_PASSWORD)))
				.as("비밀번호가 맞아도 거부한다 — 검사가 비교보다 먼저다")
				.isInstanceOf(BusinessException.class)
				.extracting(e -> ((BusinessException) e).getErrorCode())
				.isEqualTo(ErrorCode.ACCOUNT_NOT_FOUND);

		assertThat(저장된_해시(id)).isEqualTo(before);
		assertThat(this.refreshTokenRepository.findByAccountId(id))
				.as("거부된 변경은 아무것도 지우지 않는다")
				.isPresent();
	}

	// --- AU-09 계정 탈퇴 (sp-docs/plan/phase1.md §4 AU-09) ---

	/**
	 * <b>행을 지우지 않는다</b> — {@code Account.withdraw()} 의 Soft Delete 다. 행이 남고
	 * {@code uk_account_email} 이 UNIQUE 이므로 탈퇴한 이메일은 재가입에 재사용되지 않는다
	 * (sp-docs/requirements/member.md §3 규칙 1).
	 */
	@Test
	@DisplayName("탈퇴하면 deleted = true 가 되고 행은 남고 refresh_token 행이 사라진다")
	void 정상_탈퇴() {
		Long id = 계정을_만든다("withdraw@example.com");
		refresh_token_행을_만든다(id);

		this.accountService.withdraw(id, new WithdrawRequest(RAW_PASSWORD));

		assertThat(this.accountRepository.findById(id))
				.as("행 삭제가 아니다 (sp-docs/plan/phase1.md §4 AU-09 완료 기준)")
				.isPresent();
		assertThat(this.accountRepository.findById(id).orElseThrow().isDeleted()).isTrue();
		assertThat(this.refreshTokenRepository.findByAccountId(id))
				.as("탈퇴 시 Refresh Token 을 삭제한다 (sp-docs/requirements/member.md §3 규칙 4)")
				.isEmpty();
	}

	@Test
	@DisplayName("탈퇴 요청의 비밀번호가 틀리면 AU004 이고 deleted 가 그대로 false 다")
	void 탈퇴_비밀번호_불일치() {
		Long id = 계정을_만든다("wrongpw@example.com");
		refresh_token_행을_만든다(id);

		assertThatThrownBy(() -> this.accountService.withdraw(id, new WithdrawRequest("Other1!pw")))
				.isInstanceOf(BusinessException.class)
				.extracting(e -> ((BusinessException) e).getErrorCode())
				.isEqualTo(ErrorCode.PASSWORD_MISMATCH);

		assertThat(this.accountRepository.findById(id).orElseThrow().isDeleted()).isFalse();
		assertThat(this.refreshTokenRepository.findByAccountId(id))
				.as("거부된 탈퇴는 아무것도 지우지 않는다")
				.isPresent();
	}

	/**
	 * <b>멱등이다 — 이미 탈퇴한 계정에 다시 호출해도 204 이고 아무것도 바꾸지 않는다</b>
	 * (MR-10, sp-docs/api-contract.md §2.2). HTTP 상태는
	 * {@code AccountControllerTest} 가 본다.
	 *
	 * <p>남아 있는 토큰 행이 그대로인지까지 본다. 그 상태는 운영의 정상 경로에서는 생기지
	 * 않으므로({@link #정상_탈퇴()} 가 지운다) 픽스처를 엔티티로 만든다 —
	 * {@code 탈퇴시킨다} 가 그래서 엔티티를 쓴다.
	 */
	@Test
	@DisplayName("이미 탈퇴한 계정에 다시 탈퇴하면 updated_at 과 토큰 행이 그대로다")
	void 이미_탈퇴한_계정_재호출() {
		Long id = 계정을_만든다("idempotent@example.com");
		refresh_token_행을_만든다(id);
		탈퇴시킨다(id);
		LocalDateTime updatedAt = 저장된_수정시각(id);

		assertThatCode(() -> this.accountService.withdraw(id, new WithdrawRequest(RAW_PASSWORD)))
				.doesNotThrowAnyException();

		assertThat(this.accountRepository.findById(id).orElseThrow().isDeleted()).isTrue();
		assertThat(저장된_수정시각(id))
				.as("닫힌 행에 쓰기가 닿지 않는다 — account 에 deleted_at 이 없어 updated_at 이 "
						+ "탈퇴 시점의 유일한 흔적이다 (sp-docs/api-contract.md §2.2)")
				.isEqualTo(updatedAt);
		assertThat(this.refreshTokenRepository.findByAccountId(id))
				.as("아무것도 바꾸지 않는다 (sp-docs/api-contract.md §2.2)")
				.isPresent();
	}

	/**
	 * <b>{@code deleted} 검사가 비밀번호 비교보다 먼저다</b> (sp-docs/api-contract.md §2.2).
	 * {@code PATCH /me/password} 와 <b>같은 순서이고 결론만 반대다</b> — 그쪽은 404 로 거부하고
	 * ({@link #탈퇴한_계정()}) 이쪽은 204 로 통과한다. 재확인이 보호하는 것은 <b>계정을 닫는
	 * 행위</b>이고 이미 닫힌 계정에는 보호할 상태가 없다.
	 */
	@Test
	@DisplayName("이미 탈퇴한 계정은 비밀번호가 틀려도 AU004 가 아니다")
	void 이미_탈퇴한_계정_재호출_비밀번호_틀림() {
		Long id = 계정을_만든다("idem-wrongpw@example.com");
		탈퇴시킨다(id);
		LocalDateTime updatedAt = 저장된_수정시각(id);

		assertThatCode(() -> this.accountService.withdraw(id, new WithdrawRequest("Other1!pw")))
				.as("검사가 비교보다 먼저다 (sp-docs/api-contract.md §2.2)")
				.doesNotThrowAnyException();

		assertThat(저장된_수정시각(id)).isEqualTo(updatedAt);
	}

	/**
	 * 토큰의 {@code sub} 가 가리키는 행이 아예 없는 경우다. <b>정본이 이 입력을 404
	 * {@code AU001} 로 정하고, 멱등의 대상이 아니라고 적는다</b> (sp-docs/api-contract.md §2.2
	 * 의 표). 멱등이 요구되는 것은 <b>이미 탈퇴한 계정</b>이고 없는 행은 그것이 아니므로
	 * {@code AccountReader} 의 {@code AU001} 을 그대로 쓴다 — {@code GET}·{@code PATCH} 와
	 * 같다. 조용히 204 로 넘기지 않는다.
	 */
	@Test
	@DisplayName("없는 계정의 탈퇴는 AU001 이다")
	void 없는_계정의_탈퇴() {
		assertThatThrownBy(() ->
				this.accountService.withdraw(999_999L, new WithdrawRequest(RAW_PASSWORD)))
				.isInstanceOf(BusinessException.class)
				.extracting(e -> ((BusinessException) e).getErrorCode())
				.isEqualTo(ErrorCode.ACCOUNT_NOT_FOUND);
	}

	/**
	 * 검증표의 마지막 두 줄 — <b>"변경 중 예외 발생 → 비밀번호와 토큰 둘 다 롤백. 두 단언이
	 * 각각 반증 가능해야 한다"</b>와 <b>"한 번의 호출에 커밋이 정확히 한 번"</b>
	 * (sp-docs/plan/phase1.md §4 AU-08).
	 *
	 * <p><b>왜 중첩 클래스인가</b> — 빈 둘을 바꿔야 한다. {@code RefreshTokenRepository} 는
	 * 삭제 지점에 실패를 주입하기 위해서고, {@code PlatformTransactionManager} 는 커밋을 세기
	 * 위해서다. 빈을 교체하면 컨텍스트가 갈리므로, 바깥 테스트들이 실제 빈을 그대로 쓰도록 이
	 * 둘만 분리한다.
	 *
	 * <p><b>이 클래스의 빈은 바깥 클래스의 빈과 다른 컨텍스트에서 온다.</b> JUnit 이 바깥
	 * 인스턴스를 바깥 클래스의 {@code TestContext} 로 주입하므로 {@code AccountServiceTest.this}
	 * 의 필드에는 <b>스파이가 아닌 원래 빈</b>이 들어 있다. 그래서 검증 대상인
	 * {@code AccountService} 를 여기서 다시 주입받는다 — 바깥 것을 쓰면 스파이가 걸리지 않아
	 * 관측도 실패 주입도 일어나지 않는다.
	 *
	 * <p>데이터 준비는 바깥 헬퍼를 그대로 쓴다. 두 컨텍스트가 <b>같은 H2 DB</b>를 보므로
	 * ({@code DB_CLOSE_DELAY=-1}, sp-docs/tech-stack.md §5.3) 커밋된 행은 양쪽에서 보인다.
	 * 준비가 바깥 트랜잭션 매니저를 쓰는 덕에 커밋 집계에 섞이지도 않는다.
	 *
	 * <p><b>"한 로컬 트랜잭션"은 행위 관측만으로 확정되지 않는다</b>
	 * (sp-docs/process/review-policy.md §4.1). 규칙 4 가 금지하는 "한쪽만 반영됨"을 만드는
	 * 변이가 셋이고, <b>서로 다른 테스트에 잡힌다.</b>
	 *
	 * <table border="1">
	 * <caption>{@code changePassword} 변이별 실패 (실측)</caption>
	 * <tr><th>변이</th><th>무엇이 깨지나</th><th>겨누는 테스트</th></tr>
	 * <tr><td><b>A</b> — {@code @Transactional} 제거</td><td>트랜잭션이 아예 없다</td>
	 * <td>정상 경로 테스트들. 파생 삭제가 활성 트랜잭션을 요구해 거기서 즉시 터진다</td></tr>
	 * <tr><td><b>B</b> — {@code @Transactional(noRollbackFor = …)}</td>
	 * <td>트랜잭션은 있고 원자성만 깨진다</td>
	 * <td>{@link #둘_다_롤백된다()} <b>하나뿐</b></td></tr>
	 * <tr><td><b>C</b> — 연산마다 자기 {@code @Transactional}</td>
	 * <td><b>독립적으로 커밋되는 트랜잭션 둘</b></td>
	 * <td>{@link #커밋이_정확히_한_번이다()} — 커밋 <b>3회</b>가 센다</td></tr>
	 * </table>
	 *
	 * <p><b>C 를 행위 단언으로 잡을 수는 없다</b>(§4.1). 정상 경로는 두 효과가 여전히 둘 다
	 * 일어나므로 통과하고, 실패를 주입해도 <b>"한 트랜잭션"과 "첫 트랜잭션이 롤백된 두
	 * 트랜잭션"이 관측상 구별되지 않는다.</b> 그래서 커밋 횟수를 직접 센다.
	 *
	 * <p><b>이 셋이 잡힌다는 것은 아무것도 증명하지 않는다.</b> 앞 판의 주석은 "둘이 쌍으로만
	 * 완료 기준을 증명한다"고 적었고 C 가 그것을 반증했다 — A·B 를 모두 잡는 스위트가 C 를
	 * 통째로 통과시켰다. 변이 테스트는 반증 도구다.
	 *
	 * <p>{@link #둘_다_롤백된다()} 는 주입한 DELETE 때문에 A·C 에서도 빨개지지만 <b>거기에
	 * 기대지 않는다.</b> C 에서는 단언이 아니라 Mockito 오사용 오류로 터진다 — 변이 C 가
	 * 리포지터리 스파이까지 트랜잭션 프록시로 감싸기 때문이고, 그 형태는 의지할 것이 아니다.
	 *
	 * <p><b>AU-09 가 이 구조를 복제한다.</b> 탈퇴도 완료 기준에 "두 연산이 한 로컬
	 * 트랜잭션이다"를 갖는다. <b>롤백 테스트만 가져가면 C 가 통째로 통과한다</b> — 경계 관측을
	 * 함께 가져가야 한다.
	 */
	@Nested
	@DisplayName("비밀번호 교체와 토큰 삭제가 한 로컬 트랜잭션이다")
	class 트랜잭션_경계 {

		@DynamicPropertySource
		static void jwtPrivateKey(DynamicPropertyRegistry registry) {
			TestRsaKeys.registerPrivateKeyLocation(registry);
		}

		/** 삭제 지점에 실패를 주입한다. 나머지 메서드는 실제 빈에 위임된다. */
		@MockitoSpyBean
		private RefreshTokenRepository spyRefreshTokenRepository;

		/**
		 * <b>경계를 관측하는 지점이다.</b> {@code TransactionInterceptor} 가 이 빈으로
		 * 트랜잭션을 열고 닫으므로 커밋이 전부 여기를 지난다.
		 */
		@MockitoSpyBean
		private PlatformTransactionManager spyTransactionManager;

		/** 위 스파이들을 주입받은 쪽이다. 바깥 클래스의 것과 다른 인스턴스다. */
		@Autowired
		private AccountService accountService;

		/**
		 * <b>JPA 를 거치지 않고 읽는다.</b> 롤백 여부를 보는 것이므로 영속성 컨텍스트가 아니라
		 * 커밋된 행을 봐야 한다.
		 *
		 * <p>{@link #둘_다_롤백된다()} 는 쓰기에도 쓴다 — 거기에 이유가 적혀 있다.
		 */
		@Autowired
		private JdbcTemplate jdbcTemplate;

		/**
		 * 완료 기준 <b>"두 연산이 한 로컬 트랜잭션이다"</b>를 경계로 관측한다
		 * (sp-docs/process/review-policy.md §4.1). <b>행위 단언으로 대체할 수 없다.</b>
		 *
		 * <p><b>세는 것은 물리 트랜잭션의 커밋이다.</b> 참여 트랜잭션
		 * ({@code SimpleJpaRepository} 의 {@code readOnly} 조회 등)도 매니저의 {@code commit}
		 * 을 지나지만 {@code isNewTransaction()} 이 거짓이다 — 그것을 빼면 남는 수가 실제로
		 * 커밋된 트랜잭션의 수다.
		 */
		@Test
		@DisplayName("한 번의 호출에 물리 트랜잭션이 정확히 하나 커밋된다")
		void 커밋이_정확히_한_번이다() {
			Long id = 계정을_만든다("boundary@example.com");
			refresh_token_행을_만든다(id);

			// 준비가 끝난 뒤에 센다. 준비는 바깥 컨텍스트의 매니저를 쓰므로 섞이지 않지만,
			// 세는 구간을 changePassword 한 번으로 좁혀 두는 편이 읽기에도 분명하다
			List<TransactionStatus> 커밋된_물리_트랜잭션 = new ArrayList<>();
			willAnswer(invocation -> {
				TransactionStatus status = invocation.getArgument(0);
				if (status.isNewTransaction()) {
					커밋된_물리_트랜잭션.add(status);
				}
				return invocation.callRealMethod();
			}).given(this.spyTransactionManager).commit(any(TransactionStatus.class));

			this.accountService.changePassword(id, new PasswordChangeRequest(RAW_PASSWORD, NEW_PASSWORD));

			assertThat(커밋된_물리_트랜잭션)
					.as("비밀번호 교체와 토큰 삭제가 한 로컬 트랜잭션이다 "
							+ "(sp-docs/requirements/member.md §3 규칙 4)")
					.hasSize(1);
		}

		/**
		 * <b>스텁이 실제 삭제를 돌린 뒤에 throw 한다.</b> 그냥 {@code willThrow} 로 가로채면
		 * DELETE 가 발행될 자리가 사라져 "토큰도 롤백된다"가 <b>어떤 구현에서도 참</b>이
		 * 된다 — {@code @Transactional} 이 아예 없어도 통과하는 반증 불가능한 단언이다
		 * (sp-docs/process/review-policy.md §4.1). 되돌릴 효과를 실제로 만들어야 그 단언이
		 * 일한다.
		 *
		 * <p>비밀번호 쪽은 반대로 <b>미반영이 정상</b>이다. 준영속이 아닌 관리 엔티티의 변경이
		 * 커밋 시점에 flush 되므로, 롤백되면 쓰이지 않고 커밋되면(변이 B) 쓰인다.
		 *
		 * <p><b>삭제를 {@code JdbcTemplate} 으로 발행한다.</b> 리포지터리는 JDK 프록시이고
		 * 스파이가 그것을 {@code delegatesTo} 로 감싸므로 {@code callRealMethod()} 를 쓸 수
		 * 없다("Cannot call abstract real method"). {@code JpaTransactionManager} 가 같은
		 * {@code DataSource} 의 커넥션을 트랜잭션에 묶으므로 이 DELETE 는 <b>서비스의
		 * 트랜잭션에 참여한다</b> — 경계가 없으면 그 자리에서 커밋되고, 있으면 함께 롤백된다.
		 */
		@Test
		@DisplayName("Refresh Token 삭제가 실패하면 비밀번호도 토큰도 커밋되지 않는다")
		void 둘_다_롤백된다() {
			Long id = 계정을_만든다("rollback@example.com");
			String before = 저장된_해시(id);
			refresh_token_행을_만든다(id);

			willAnswer(invocation -> {
				// 이 문장의 짝은 RefreshTokenRepository.deleteByAccountId 다. 둘이 어긋나면
				// 아래 단언이 그 자리에서 터진다 — 영향 행 수를 버리면 0행이 되어도 조용하고,
				// 되돌릴 효과가 없으므로 토큰 단언이 반증 불가능해진다
				// (sp-docs/process/review-policy.md §4.1 "실패할 수 없는 단언을 쓰지 않는다")
				int deleted = this.jdbcTemplate.update(
						"delete from refresh_token where account_id = ?", (Long) invocation.getArgument(0));
				assertThat(deleted)
						.as("주입한 DELETE 가 실제로 행을 지워야 이 테스트가 일한다")
						.isEqualTo(1);
				throw new DataIntegrityViolationException("삭제 실패");
			}).given(this.spyRefreshTokenRepository).deleteByAccountId(anyLong());

			assertThatThrownBy(() -> this.accountService
					.changePassword(id, new PasswordChangeRequest(RAW_PASSWORD, NEW_PASSWORD)))
					.isInstanceOf(DataIntegrityViolationException.class);

			assertThat(커밋된_해시(id))
					.as("두 연산이 한 로컬 트랜잭션이다 (sp-docs/requirements/member.md §3 규칙 4)")
					.isEqualTo(before);
			assertThat(커밋된_토큰_행_수(id))
					.as("발행된 DELETE 도 함께 되돌아간다 — 행이 남아 있어야 한다")
					.isEqualTo(1);
		}

		private String 커밋된_해시(Long accountId) {
			return this.jdbcTemplate.queryForObject(
					"select password from account where id = ?", String.class, accountId);
		}

		private long 커밋된_토큰_행_수(Long accountId) {
			return this.jdbcTemplate.queryForObject(
					"select count(*) from refresh_token where account_id = ?", Long.class, accountId);
		}

	}

	/**
	 * AU-09 검증표의 마지막 두 줄 — <b>"탈퇴 중 예외 발생 → {@code deleted} 와 토큰 둘 다 롤백.
	 * 두 단언이 각각 반증 가능해야 한다"</b>와 <b>"한 번의 호출에 커밋이 정확히 한 번 — 변이
	 * 셋(A·B·C)을 돌린다"</b> (sp-docs/plan/phase1.md §4 AU-09).
	 *
	 * <p>구조는 AU-08 의 {@link 트랜잭션_경계} 와 같고 이유도 같다 — 빈 둘을 바꿔야 하므로
	 * 중첩 클래스이고, 바깥 클래스의 필드에는 스파이가 아닌 원래 빈이 들어 있으므로
	 * {@code AccountService} 를 여기서 다시 주입받는다.
	 *
	 * <p><b>롤백 테스트만 복제하면 변이 C 가 통째로 통과한다</b>
	 * (sp-docs/process/review-policy.md §4.1). 그래서 경계 관측을 함께 둔다. 탈퇴에서는 C 의
	 * 손상이 비밀번호 변경보다 크다 — <b>{@code deleted = true} 가 커밋되고 토큰이 살아남으면
	 * 탈퇴한 계정이 14일간 토큰을 갱신한다.</b>
	 *
	 * <table border="1">
	 * <caption>{@code withdraw} 변이별 실패 (실측)</caption>
	 * <tr><th>변이</th><th>무엇이 깨지나</th><th>겨누는 테스트</th></tr>
	 * <tr><td><b>A</b> — {@code @Transactional} 제거</td><td>트랜잭션이 아예 없다</td>
	 * <td>정상 경로 테스트들. 파생 삭제가 활성 트랜잭션을 요구해 거기서 터진다</td></tr>
	 * <tr><td><b>B</b> — {@code @Transactional(noRollbackFor = …)}</td>
	 * <td>트랜잭션은 있고 원자성만 깨진다</td>
	 * <td>{@link #둘_다_롤백된다()} <b>하나뿐</b></td></tr>
	 * <tr><td><b>C</b> — 연산마다 자기 {@code @Transactional}</td>
	 * <td><b>독립적으로 커밋되는 트랜잭션 둘</b></td>
	 * <td>{@link #커밋이_정확히_한_번이다()} — 커밋 <b>3회</b>가 센다</td></tr>
	 * </table>
	 *
	 * <p><b>이 셋이 잡힌다는 것은 아무것도 증명하지 않는다</b>(§4.1). 변이 테스트는 반증
	 * 도구다 — 잡히지 않은 변이가 발견이다.
	 */
	@Nested
	@DisplayName("deleted = true 와 토큰 삭제가 한 로컬 트랜잭션이다")
	class 탈퇴_트랜잭션_경계 {

		@DynamicPropertySource
		static void jwtPrivateKey(DynamicPropertyRegistry registry) {
			TestRsaKeys.registerPrivateKeyLocation(registry);
		}

		/** 삭제 지점에 실패를 주입한다. 나머지 메서드는 실제 빈에 위임된다. */
		@MockitoSpyBean
		private RefreshTokenRepository spyRefreshTokenRepository;

		/**
		 * <b>경계를 관측하는 지점이다.</b> {@code TransactionInterceptor} 가 이 빈으로
		 * 트랜잭션을 열고 닫으므로 커밋이 전부 여기를 지난다.
		 */
		@MockitoSpyBean
		private PlatformTransactionManager spyTransactionManager;

		/** 위 스파이들을 주입받은 쪽이다. 바깥 클래스의 것과 다른 인스턴스다. */
		@Autowired
		private AccountService accountService;

		/** <b>JPA 를 거치지 않고 읽는다.</b> 영속성 컨텍스트가 아니라 커밋된 행을 봐야 한다. */
		@Autowired
		private JdbcTemplate jdbcTemplate;

		/**
		 * 완료 기준 <b>"두 연산이 한 로컬 트랜잭션이다"</b>를 경계로 관측한다
		 * (sp-docs/process/review-policy.md §4.1). <b>행위 단언으로 대체할 수 없다</b> —
		 * 변이 C 는 두 효과가 여전히 둘 다 일어나므로 정상 경로를 통과하고, 실패를 주입해도
		 * "한 트랜잭션"과 "첫 트랜잭션이 롤백된 두 트랜잭션"이 관측상 구별되지 않는다.
		 *
		 * <p><b>{@code isNewTransaction()} 이 참인 커밋만 센다.</b> {@code AccountReader} 의
		 * {@code findById} 같은 참여 트랜잭션도 매니저의 {@code commit} 을 지나므로, 필터가
		 * 없으면 <b>올바른 구현도 1을 넘는다.</b>
		 */
		@Test
		@DisplayName("한 번의 호출에 물리 트랜잭션이 정확히 하나 커밋된다")
		void 커밋이_정확히_한_번이다() {
			Long id = 계정을_만든다("boundary-withdraw@example.com");
			refresh_token_행을_만든다(id);

			// 준비가 끝난 뒤에 센다. 준비는 바깥 컨텍스트의 매니저를 쓰므로 섞이지 않지만,
			// 세는 구간을 withdraw 한 번으로 좁혀 두는 편이 읽기에도 분명하다
			List<TransactionStatus> 커밋된_물리_트랜잭션 = new ArrayList<>();
			willAnswer(invocation -> {
				TransactionStatus status = invocation.getArgument(0);
				if (status.isNewTransaction()) {
					커밋된_물리_트랜잭션.add(status);
				}
				return invocation.callRealMethod();
			}).given(this.spyTransactionManager).commit(any(TransactionStatus.class));

			this.accountService.withdraw(id, new WithdrawRequest(RAW_PASSWORD));

			assertThat(커밋된_물리_트랜잭션)
					.as("deleted = true 와 토큰 삭제가 한 로컬 트랜잭션이다 "
							+ "(sp-docs/requirements/member.md §3 규칙 4)")
					.hasSize(1);
		}

		/**
		 * <b>스텁이 실제 삭제를 돌린 뒤에 throw 한다.</b> 그냥 {@code willThrow} 로 가로채면
		 * DELETE 가 발행될 자리가 사라져 "토큰도 롤백된다"가 <b>어떤 구현에서도 참</b>이 된다
		 * — {@code @Transactional} 이 아예 없어도 통과하는 반증 불가능한 단언이다
		 * (sp-docs/process/review-policy.md §4.1). 되돌릴 효과를 실제로 만들어야 단언이 일한다.
		 *
		 * <p>{@code deleted} 쪽은 반대로 <b>미반영이 정상</b>이다. 관리 엔티티의 변경이 커밋
		 * 시점에 flush 되므로, 롤백되면 쓰이지 않고 커밋되면(변이 B) {@code true} 가 쓰인다.
		 *
		 * <p><b>삭제를 {@code JdbcTemplate} 으로 발행한다.</b> 리포지터리는 JDK 프록시이고
		 * 스파이가 그것을 {@code delegatesTo} 로 감싸므로 {@code callRealMethod()} 를 쓸 수
		 * 없다("Cannot call abstract real method"). {@code JpaTransactionManager} 가 같은
		 * {@code DataSource} 의 커넥션을 트랜잭션에 묶으므로 이 DELETE 는 <b>서비스의
		 * 트랜잭션에 참여한다</b> — 경계가 없으면 그 자리에서 커밋되고, 있으면 함께 롤백된다.
		 */
		@Test
		@DisplayName("Refresh Token 삭제가 실패하면 deleted 도 토큰도 커밋되지 않는다")
		void 둘_다_롤백된다() {
			Long id = 계정을_만든다("rollback-withdraw@example.com");
			refresh_token_행을_만든다(id);

			willAnswer(invocation -> {
				// 이 문장의 짝은 RefreshTokenRepository.deleteByAccountId 다. 둘이 어긋나면
				// 아래 단언이 그 자리에서 터진다 — 영향 행 수를 버리면 0행이 되어도 조용하고,
				// 되돌릴 효과가 없으므로 토큰 단언이 반증 불가능해진다
				// (sp-docs/process/review-policy.md §4.1 "실패할 수 없는 단언을 쓰지 않는다")
				int deleted = this.jdbcTemplate.update(
						"delete from refresh_token where account_id = ?", (Long) invocation.getArgument(0));
				assertThat(deleted)
						.as("주입한 DELETE 가 실제로 행을 지워야 이 테스트가 일한다")
						.isEqualTo(1);
				throw new DataIntegrityViolationException("삭제 실패");
			}).given(this.spyRefreshTokenRepository).deleteByAccountId(anyLong());

			assertThatThrownBy(() ->
					this.accountService.withdraw(id, new WithdrawRequest(RAW_PASSWORD)))
					.isInstanceOf(DataIntegrityViolationException.class);

			assertThat(커밋된_탈퇴_여부(id))
					.as("두 연산이 한 로컬 트랜잭션이다 (sp-docs/requirements/member.md §3 규칙 4)")
					.isFalse();
			assertThat(커밋된_토큰_행_수(id))
					.as("발행된 DELETE 도 함께 되돌아간다 — 행이 남아 있어야 한다")
					.isEqualTo(1);
		}

		private boolean 커밋된_탈퇴_여부(Long accountId) {
			return this.jdbcTemplate.queryForObject(
					"select deleted from account where id = ?", Boolean.class, accountId);
		}

		private long 커밋된_토큰_행_수(Long accountId) {
			return this.jdbcTemplate.queryForObject(
					"select count(*) from refresh_token where account_id = ?", Long.class, accountId);
		}

	}

	// --- AU-16 이메일 인증 확인 (sp-docs/requirements/member.md §11.2) ---

	/**
	 * 확인은 계정을 읽고 고쳐 쓴다. 그 사이에 다른 연결이 탈퇴({@code deleted = true})를 커밋하려 하면 <b>확인의 커밋을
	 * 기다려야 한다</b> — 기다리지 않고 먼저 커밋되면 확인의 쓰기가 읽어 둔 {@code deleted = false} 로 그 행을 덮어 탈퇴한
	 * 계정이 되살아난다. 「닫힌 행에는 쓰지 않는다」(sp-docs/requirements/member.md §11.4 의 같은 이유)를 지키는 것이
	 * 계정의 잠금 읽기({@code AccountRepository.findByIdForUpdate})다.
	 *
	 * <p>확인을 바깥 트랜잭션 안에서 불러 그 커밋을 테스트가 쥔다 — 확인이 끝났고 아직 커밋하지 않은 때에 다른 연결의
	 * 탈퇴를 시작한다. 탈퇴는 잠긴 행을 기다리고, 확인이 커밋한 뒤에 들어간다.
	 */
	@Test
	@DisplayName("확인이 읽은 계정 행은 커밋까지 잠긴다 — 그 사이에 커밋하려는 탈퇴를 덮지 않는다")
	void 확인_사이의_탈퇴를_덮지_않는다() throws Exception {
		Long id = 미인증_계정을_만든다("au16-lock@example.com");
		String token = 인증_토큰을_심는다(id);
		TransactionTemplate outer = new TransactionTemplate(this.transactionManager);
		ExecutorService otherConnection = Executors.newSingleThreadExecutor();
		try {
			List<Boolean> 확인_커밋_전에_끝났다 = new ArrayList<>();
			Future<Integer> withdrawal = outer.execute(status -> {
				this.accountService.confirmEmailVerification(token);
				Future<Integer> started = otherConnection.submit(() ->
						this.jdbcTemplate.update("update account set deleted = true where id = ?", id));
				확인_커밋_전에_끝났다.add(끝났는가(started, 300));
				return started;
			});

			assertThat(withdrawal.get(5, TimeUnit.SECONDS)).as("탈퇴는 확인이 커밋한 뒤에 들어간다").isOne();
			assertThat(커밋된_탈퇴_여부(id)).as("확인의 쓰기가 탈퇴를 덮지 않았다").isTrue();
			assertThat(커밋된_인증_시각(id)).as("확인은 탈퇴보다 먼저 커밋됐다").isNotNull();
			assertThat(확인_커밋_전에_끝났다).as("탈퇴가 확인의 커밋을 기다렸다").containsExactly(false);
		} finally {
			otherConnection.shutdownNow();
		}
	}

	/**
	 * 확인의 트랜잭션 경계(sp-docs/process/review-policy.md §4.1)와 가입이 발급을 넘기는 때
	 * (sp-docs/plan/phase2-auth-member.md AU-16 의 검증 표).
	 *
	 * <p>발송 실행기를 대역으로 바꾼다 — 받은 작업을 돌리지 않고 Mockito 가 받은 횟수와 작업을 남긴다. 그래서
	 * 「트랜잭션이 열린 동안 받은 작업」을 기다림 없이 셀 수 있고, 받은 발급 작업은 테스트가 이 스레드에서 돌린다.
	 *
	 * <p>Hibernate 가 준비한 SQL 을 적는 기록기({@link RecordingStatementInspector})도 이 컨텍스트에 단다 — 확인이 계정을
	 * 잠금 읽기로 읽는지를 SQL 로 본다. 실행기가 대역이라 받은 작업이 다른 스레드에서 SQL 을 내지 않는다.
	 */
	@Nested
	@TestPropertySource(properties = "spring.jpa.properties.hibernate.session_factory.statement_inspector="
			+ "com.example.auth.support.RecordingStatementInspector")
	@DisplayName("인증 확인·가입 발급의 트랜잭션 경계")
	class 인증_트랜잭션_경계 {

		@DynamicPropertySource
		static void jwtPrivateKey(DynamicPropertyRegistry registry) {
			TestRsaKeys.registerPrivateKeyLocation(registry);
		}

		/** 커밋이 전부 지나는 곳. {@code isNewTransaction()} 이 참인 커밋만 센다. */
		@MockitoSpyBean
		private PlatformTransactionManager spyTransactionManager;

		/** 발송 실행기의 대역. 받은 작업을 돌리지 않는다. */
		@MockitoBean(name = MailExecutorConfig.MAIL_EXECUTOR)
		private ThreadPoolTaskExecutor mailExecutorDouble;

		/** 재발송을 부른 스레드가 계정을 찾지 않는지 본다. 나머지는 실제 빈에 위임된다. */
		@MockitoSpyBean
		private AccountRepository accountRepository;

		/** 이 클래스의 대역들을 주입받은 쪽이다. 바깥 클래스의 것과 다른 인스턴스다. */
		@Autowired
		private AccountService accountService;

		@Autowired
		private AccountTokenRepository accountTokenRepository;

		@Test
		@DisplayName("가입을 바깥 트랜잭션 안에서 하면 열린 동안 넘긴 발급이 없고, 되돌리면 끝까지 없다")
		void 가입이_되돌려지면_발급을_넘기지_않는다() {
			TransactionTemplate outer = new TransactionTemplate(this.spyTransactionManager);

			outer.executeWithoutResult(status -> {
				this.accountService.create(new AccountCreateRequest("au16-signup-rollback@example.com", RAW_PASSWORD));
				verify(this.mailExecutorDouble, never()).execute(any(Runnable.class));
				status.setRollbackOnly();
			});

			verify(this.mailExecutorDouble, never()).execute(any(Runnable.class));
			assertThat(this.accountRepository.existsByEmail("au16-signup-rollback@example.com")).isFalse();
		}

		@Test
		@DisplayName("가입을 바깥 트랜잭션 안에서 하면 열린 동안 넘긴 발급이 없고, 커밋하면 그때 하나다")
		void 가입이_커밋되면_그때_발급을_넘긴다() {
			TransactionTemplate outer = new TransactionTemplate(this.spyTransactionManager);

			outer.executeWithoutResult(status -> {
				this.accountService.create(new AccountCreateRequest("au16-signup-commit@example.com", RAW_PASSWORD));
				verify(this.mailExecutorDouble, never()).execute(any(Runnable.class));
			});

			verify(this.mailExecutorDouble, times(1)).execute(any(Runnable.class));
		}

		/**
		 * 완료 기준 「요청 스레드는 DB 일을 하지 않는다」(sp-docs/security.md §12). 재발송을 부른 스레드는 계정을 찾지도
		 * 트랜잭션을 열지도 않고 발급 작업 하나를 넘긴다. 계정 찾기는 그 작업이 한다 — 넘겨받은 작업을 돌리면 그때 찾는다.
		 */
		@Test
		@DisplayName("재발송은 발급 작업을 넘기기만 한다 — 부른 스레드는 계정을 찾지도 트랜잭션을 열지도 않는다")
		void 재발송은_작업을_넘기기만_한다() {
			Long id = 미인증_계정을_만든다("au16-resend-handover@example.com");
			clearInvocations(this.accountRepository, this.spyTransactionManager);

			this.accountService.resendVerification("au16-resend-handover@example.com");

			verifyNoInteractions(this.accountRepository);
			verify(this.spyTransactionManager, never()).getTransaction(any());
			ArgumentCaptor<Runnable> handedOver = ArgumentCaptor.forClass(Runnable.class);
			verify(this.mailExecutorDouble).execute(handedOver.capture());

			handedOver.getValue().run();
			verify(this.accountRepository).findByEmail("au16-resend-handover@example.com");
			assertThat(this.accountTokenRepository.findAll()).extracting(AccountToken::getAccountId)
					.as("넘겨받은 작업이 토큰을 만든다").containsExactly(id);
		}

		/**
		 * 완료 기준 「트랜잭션 경계를 관측한다 — 한 번의 확인에 커밋이 한 번이다」. 사용 처리·탈퇴 검사·인증 시각이 서로
		 * 다른 트랜잭션으로 갈라지면(변이 C) 행위 단언으로는 가르지 못한다 (sp-docs/process/review-policy.md §4.1).
		 */
		@Test
		@DisplayName("한 번의 확인에 물리 트랜잭션이 정확히 하나 커밋된다")
		void 확인의_커밋이_정확히_한_번이다() {
			Long id = 미인증_계정을_만든다("au16-confirm-boundary@example.com");
			String token = 인증_토큰을_심는다(id);

			List<TransactionStatus> 커밋된_물리_트랜잭션 = 커밋을_센다();
			this.accountService.confirmEmailVerification(token);

			assertThat(커밋된_물리_트랜잭션)
					.as("확인은 한 트랜잭션이다 (sp-docs/requirements/member.md §11.2)")
					.hasSize(1);
			assertThat(커밋된_인증_시각(id)).as("그 한 번이 인증을 채웠다").isNotNull();
		}

		/**
		 * 확인이 계정을 잠금 읽기({@code AccountRepository.findByIdForUpdate})로 읽는다 — 탈퇴 검사가 보는 값이 그 읽기이고,
		 * 확인의 트랜잭션이 끝날 때까지 그 행의 다른 쓰기가 기다린다. 못박는 것은 결과가 아니라 이 구현이 고른 수단이다.
		 *
		 * <p>{@link AccountServiceTest#확인_사이의_탈퇴를_덮지_않는다()} 는 확인이 돌아온 뒤에 탈퇴를 시작하므로 읽기와 쓰기
		 * 사이에 끼어들지 못한다. 일반 읽기 뒤 곧바로 {@code saveAndFlush} 하는 변이가 그 테스트를 지났다(AU-16 리뷰가 쟀다) —
		 * 그 쓰기도 확인이 돌아오기 전에 행을 잠그기 때문이다. 그래서 확인이 낸 SQL 을 본다.
		 */
		@Test
		@DisplayName("확인은 계정 행을 잠금 읽기(for update)로 읽는다")
		void 확인은_계정을_잠금_읽기로_읽는다() {
			Long id = 미인증_계정을_만든다("au16-confirm-lock-read@example.com");
			String token = 인증_토큰을_심는다(id);
			// account 테이블을 읽는 SELECT. account_token·account_id 는 뒤에 밑줄이 이어져 \b 에 걸리지 않는다
			Pattern accountRead = Pattern.compile("(?is)^\\s*select\\b.*\\baccount\\b");

			RecordingStatementInspector.clear();
			this.accountService.confirmEmailVerification(token);

			assertThat(RecordingStatementInspector.statements())
					.filteredOn(sql -> accountRead.matcher(sql).find())
					.as("확인이 account 행을 읽은 SELECT")
					.isNotEmpty()
					.allSatisfy(sql -> assertThat(sql).as("잠금 읽기다").containsPattern("(?i)\\bfor update\\b"));
		}

		/**
		 * 가입이 넘긴 발급 작업 한 번 — 앞 토큰 지우기와 새 토큰 넣기가 한 트랜잭션이다 (AU-15 의 작업 순서,
		 * sp-docs/requirements/member.md §11.5 마지막 문단). AU-15 리뷰가 그 경계를 못박는 테스트가 없다고 지적했다 — 같은
		 * 관측으로 덮는다.
		 */
		@Test
		@DisplayName("가입이 넘긴 발급 작업 한 번에 물리 트랜잭션이 정확히 하나 커밋된다 — 앞 토큰을 지우고 새 토큰을 넣는다")
		void 발급_작업의_커밋이_정확히_한_번이다() {
			Long id = this.accountService.create(
					new AccountCreateRequest("au16-issue-boundary@example.com", RAW_PASSWORD)).accountId();
			String 앞_토큰의_해시 = AccountTokens.hash(인증_토큰을_심는다(id));
			ArgumentCaptor<Runnable> handedOver = ArgumentCaptor.forClass(Runnable.class);
			verify(this.mailExecutorDouble).execute(handedOver.capture());

			List<TransactionStatus> 커밋된_물리_트랜잭션 = 커밋을_센다();
			handedOver.getValue().run();

			assertThat(커밋된_물리_트랜잭션)
					.as("앞 토큰 지우기와 새 토큰 넣기가 한 트랜잭션이다")
					.hasSize(1);
			List<String> 남은_해시 = this.accountTokenRepository.findAll().stream()
					.filter(row -> row.getAccountId().equals(id))
					.map(AccountToken::getTokenHash)
					.toList();
			assertThat(남은_해시).as("새 토큰 하나만 남는다").hasSize(1).doesNotContain(앞_토큰의_해시);
			verify(this.mailExecutorDouble, times(2)).execute(any(Runnable.class));
		}

		/** 지금부터 커밋되는 물리 트랜잭션을 모은다. 준비가 끝난 뒤에 부른다. */
		private List<TransactionStatus> 커밋을_센다() {
			List<TransactionStatus> committed = new ArrayList<>();
			willAnswer(invocation -> {
				TransactionStatus status = invocation.getArgument(0);
				if (status.isNewTransaction()) {
					committed.add(status);
				}
				return invocation.callRealMethod();
			}).given(this.spyTransactionManager).commit(any(TransactionStatus.class));
			return committed;
		}

		private Long 미인증_계정을_만든다(String email) {
			return this.accountRepository.saveAndFlush(Account.builder()
					.email(email)
					// 해시가 아니다. 확인은 비밀번호를 읽지 않는다 (sp-docs/requirements/member.md §10.2)
					.password("test-not-a-hash-au16")
					.build()).getId();
		}

		private String 인증_토큰을_심는다(Long accountId) {
			String token = AccountTokens.generate();
			this.accountTokenRepository.saveAndFlush(AccountToken.issue(accountId, TokenPurpose.EMAIL_VERIFICATION,
					AccountTokens.hash(token), Duration.ofHours(24), AccountServiceTest.this.clock));
			return token;
		}

	}

	/** 시간 안에 끝났으면 참, 아니면 거짓. 끝나지 않은 작업을 취소하지 않는다. */
	private static boolean 끝났는가(Future<?> future, long millis) {
		try {
			future.get(millis, TimeUnit.MILLISECONDS);
			return true;
		} catch (TimeoutException e) {
			return false;
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	/** 비밀번호를 쓰지 않는 미인증 계정. 가입({@code create})으로 만들지 않는다 — 가입은 다른 스레드에서 토큰을 만든다. */
	private Long 미인증_계정을_만든다(String email) {
		return this.accountRepository.saveAndFlush(Account.builder()
				.email(email)
				// 해시가 아니다. 확인은 비밀번호를 읽지 않는다 (sp-docs/requirements/member.md §10.2)
				.password("test-not-a-hash-au16")
				.build()).getId();
	}

	/** 그 계정의 인증 토큰 행을 심고 원문을 돌려준다. 저장은 해시뿐이다 (sp-docs/domain-model.md §2.4). */
	private String 인증_토큰을_심는다(Long accountId) {
		String token = AccountTokens.generate();
		this.accountTokenRepository.saveAndFlush(AccountToken.issue(accountId, TokenPurpose.EMAIL_VERIFICATION,
				AccountTokens.hash(token), Duration.ofHours(24), this.clock));
		return token;
	}

	private boolean 커밋된_탈퇴_여부(Long accountId) {
		return this.jdbcTemplate.queryForObject("select deleted from account where id = ?", Boolean.class, accountId);
	}

	private LocalDateTime 커밋된_인증_시각(Long accountId) {
		return this.jdbcTemplate.queryForObject(
				"select email_verified_at from account where id = ?", LocalDateTime.class, accountId);
	}

	/** seed 행을 뺀 수. 절대 개수로 단언하면 seed 유무에 따라 결과가 바뀐다. */
	private long 테스트가_만든_계정_수() {
		return this.accountRepository.findAll().stream()
				.filter(account -> !ADMIN_EMAIL.equals(account.getEmail()))
				.count();
	}

	/** 비밀번호가 {@link #RAW_PASSWORD} 인 계정. 해싱은 실제 경로({@code create})가 한다. */
	private Long 계정을_만든다(String email) {
		return this.accountService.create(new AccountCreateRequest(email, RAW_PASSWORD)).accountId();
	}

	private String 저장된_해시(Long accountId) {
		return this.accountRepository.findById(accountId).orElseThrow().getPassword();
	}

	/**
	 * AU-09 — "닫힌 행에 쓰기가 닿지 않는다"를 보는 값. {@code account} 에 {@code deleted_at}
	 * 컬럼이 없어 {@code updated_at} 이 탈퇴 시점의 유일한 흔적이다
	 * (sp-docs/api-contract.md §2.2).
	 */
	private LocalDateTime 저장된_수정시각(Long accountId) {
		return this.accountRepository.findById(accountId).orElseThrow().getUpdatedAt();
	}

	/**
	 * 엔티티로 직접 탈퇴시킨다. <b>{@code withdraw} 를 쓰지 않는 것이 의도다</b> — 그쪽은
	 * Refresh Token 을 함께 지우므로 "탈퇴했는데 토큰 행이 남아 있는" 상태를 만들 수 없고,
	 * {@link #이미_탈퇴한_계정_재호출()} 이 보는 "아무것도 바꾸지 않는다"가 그 상태를 요구한다.
	 */
	private void 탈퇴시킨다(Long accountId) {
		Account account = this.accountRepository.findById(accountId).orElseThrow();
		account.withdraw();
		this.accountRepository.saveAndFlush(account);
	}

	/**
	 * 계정의 Refresh Token 행. <b>토큰 값을 실제 발급 경로로 만든다</b> —
	 * {@code refresh_token.token} 은 길이 제약이 의미를 갖는 컬럼이고(1024, AU-03R) 짧은 더미로
	 * 저장만 확인하면 그 제약을 보지 못한다 (sp-docs/conventions.md §9.2).
	 */
	private RefreshToken refresh_token_행을_만든다(Long accountId) {
		Account account = this.accountRepository.findById(accountId).orElseThrow();
		return this.refreshTokenRepository.saveAndFlush(RefreshToken.builder()
				.accountId(accountId)
				.token(this.jwtTokenProvider.issue(accountId, account.getRole()).refreshToken())
				.expiresAt(LocalDateTime.now().plus(this.jwtTokenProvider.getRefreshTokenValidity()))
				.build());
	}

}
