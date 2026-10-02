package com.example.auth.account.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import com.example.auth.account.dto.AccountCreateRequest;
import com.example.auth.account.dto.AccountResponse;
import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.Role;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.global.error.BusinessException;
import com.example.auth.global.error.ErrorCode;
import com.example.auth.support.TestRsaKeys;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * sp-docs/plan/phase1.md §4 AU-05 의 "검증" 표 중 저장 쪽을 테스트로 옮긴 것이다.
 * HTTP 상태·응답 본문은 {@link com.example.auth.account.controller.AccountControllerTest} 가 본다.
 *
 * <p>실제 {@code PasswordEncoder}(BCrypt strength 10) 와 H2 를 함께 쓴다. 해싱을 스텁으로
 * 바꾸면 "평문이 저장되지 않는다"가 검증되지 않는다.
 */
@SpringBootTest
@ActiveProfiles("test")
class AccountServiceTest {

	private static final String RAW_PASSWORD = "Passw0rd!";

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

	/**
	 * <b>seed 행은 남긴다.</b> H2 는 테스트 클래스 사이에 공유되므로
	 * ({@code DB_CLOSE_DELAY=-1}, sp-docs/tech-stack.md §5.3) 여기서 지우면
	 * {@code AdminSeedTest} 가 자기와 무관한 이유로 깨진다.
	 */
	@AfterEach
	void 정리() {
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
		AccountService service = new AccountService(stub, this.passwordEncoder);

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

	/** seed 행을 뺀 수. 절대 개수로 단언하면 seed 유무에 따라 결과가 바뀐다. */
	private long 테스트가_만든_계정_수() {
		return this.accountRepository.findAll().stream()
				.filter(account -> !ADMIN_EMAIL.equals(account.getEmail()))
				.count();
	}

}
