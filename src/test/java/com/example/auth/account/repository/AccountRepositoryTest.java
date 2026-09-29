package com.example.auth.account.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.Role;
import com.example.auth.account.support.AccountReader;
import com.example.auth.global.config.JpaConfig;
import com.example.auth.global.error.BusinessException;
import com.example.auth.global.error.ErrorCode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;

/**
 * sp-docs/plan/phase1.md §4 AU-03 의 "검증" 표 중 account 쪽을 테스트로 옮긴 것이다.
 *
 * <p>{@code replace = NONE} 이 필수다. {@code @DataJpaTest} 의 기본값은 DataSource 를
 * {@code jdbc:h2:mem:<uuid>} 로 교체해 {@code MODE=MySQL} 을 날려버린다
 * (sp-docs/tech-stack.md §5.2). 그 URL 로 실제 돌고 있는지는
 * {@link com.example.auth.TestDatabaseEnvironmentTest} 가 확인한다.
 *
 * <p>스키마는 Flyway 가 만들고 {@code ddl-auto: validate} 가 엔티티와 대조한다. 이 클래스가
 * 로딩되는 것 자체가 마이그레이션과 엔티티 매핑의 일치를 뜻한다.
 *
 * <p>{@code JpaConfig} 를 {@code @Import} 하는 이유 — {@code @DataJpaTest} 슬라이스는
 * {@code @Configuration} 을 컴포넌트 스캔하지 않으므로 {@code @EnableJpaAuditing} 이 빠진다.
 * 그러면 {@code created_at} 이 NULL 로 들어가 INSERT 가 실패한다. {@code AccountReader} 도
 * 같은 이유로 직접 올린다.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({JpaConfig.class, AccountReader.class})
@ActiveProfiles("test")
class AccountRepositoryTest {

	private static final String RAW_ENCODED_PASSWORD = "$2a$10$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQ";

	@Autowired
	private TestEntityManager em;

	@Autowired
	private AccountRepository accountRepository;

	@Autowired
	private AccountReader accountReader;

	@Test
	@DisplayName("저장 후 조회하면 모든 필드가 일치한다")
	void 저장_후_조회() {
		Account saved = accountRepository.saveAndFlush(Account.builder()
				.email("user@example.com")
				.password(RAW_ENCODED_PASSWORD)
				.role(Role.ADMIN)
				.build());
		em.clear();

		Account found = accountRepository.findById(saved.getId()).orElseThrow();

		assertThat(found.getId()).isEqualTo(saved.getId());
		assertThat(found.getEmail()).isEqualTo("user@example.com");
		assertThat(found.getPassword()).isEqualTo(RAW_ENCODED_PASSWORD);
		assertThat(found.getRole()).isEqualTo(Role.ADMIN);
		assertThat(found.isDeleted()).isFalse();
	}

	@Test
	@DisplayName("role 이 문자열(USER/ADMIN)로 저장된다")
	void role_이_문자열로_저장된다() {
		Long id = accountRepository.saveAndFlush(Account.builder()
				.email("admin@example.com")
				.password(RAW_ENCODED_PASSWORD)
				.role(Role.ADMIN)
				.build()).getId();
		em.clear();

		Object stored = em.getEntityManager()
				.createNativeQuery("select role from account where id = :id")
				.setParameter("id", id)
				.getSingleResult();

		assertThat(stored).isEqualTo("ADMIN");
	}

	@Test
	@DisplayName("중복 email 을 저장하면 DataIntegrityViolationException 이 난다")
	void 중복_email_저장() {
		accountRepository.saveAndFlush(Account.builder()
				.email("dup@example.com")
				.password(RAW_ENCODED_PASSWORD)
				.build());
		Account duplicate = Account.builder()
				.email("dup@example.com")
				.password(RAW_ENCODED_PASSWORD)
				.build();

		assertThatThrownBy(() -> accountRepository.saveAndFlush(duplicate))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("저장하면 createdAt·updatedAt 이 자동으로 채워진다")
	void 감사_필드가_채워진다() {
		Account saved = accountRepository.saveAndFlush(Account.builder()
				.email("audit@example.com")
				.password(RAW_ENCODED_PASSWORD)
				.build());

		assertThat(saved.getCreatedAt()).isNotNull();
		assertThat(saved.getUpdatedAt()).isNotNull();
	}

	@Test
	@DisplayName("role·deleted 를 지정하지 않으면 USER·false 다")
	void 기본값() {
		Account saved = accountRepository.saveAndFlush(Account.builder()
				.email("default@example.com")
				.password(RAW_ENCODED_PASSWORD)
				.build());
		em.clear();

		Account found = accountRepository.findById(saved.getId()).orElseThrow();

		assertThat(found.getRole()).isEqualTo(Role.USER);
		assertThat(found.isDeleted()).isFalse();
	}

	@Test
	@DisplayName("changePassword() 는 비밀번호만 바꾼다")
	void 비밀번호_변경() {
		Long id = accountRepository.saveAndFlush(Account.builder()
				.email("pw@example.com")
				.password(RAW_ENCODED_PASSWORD)
				.role(Role.ADMIN)
				.build()).getId();
		em.clear();
		String newEncoded = "$2a$10$ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210zyxwvutsrqponmlkj";

		accountRepository.findById(id).orElseThrow().changePassword(newEncoded);
		em.flush();
		em.clear();

		Account found = accountRepository.findById(id).orElseThrow();
		assertThat(found.getPassword()).isEqualTo(newEncoded);
		assertThat(found.getEmail()).isEqualTo("pw@example.com");
		assertThat(found.getRole()).isEqualTo(Role.ADMIN);
		assertThat(found.isDeleted()).isFalse();
	}

	@Test
	@DisplayName("withdraw() 는 deleted 만 true 로 바꾸고 행은 남긴다")
	void 탈퇴() {
		Long id = accountRepository.saveAndFlush(Account.builder()
				.email("bye@example.com")
				.password(RAW_ENCODED_PASSWORD)
				.build()).getId();
		em.clear();

		Account account = accountRepository.findById(id).orElseThrow();
		assertThat(account.isActive()).isTrue();
		account.withdraw();
		em.flush();
		em.clear();

		Account found = accountRepository.findById(id).orElseThrow();
		assertThat(found.isDeleted()).isTrue();
		assertThat(found.isActive()).isFalse();
		assertThat(found.getEmail()).isEqualTo("bye@example.com");
	}

	@Test
	@DisplayName("탈퇴한 계정의 email 은 재사용할 수 없다")
	void 탈퇴한_email_재사용_불가() {
		Account account = accountRepository.saveAndFlush(Account.builder()
				.email("reuse@example.com")
				.password(RAW_ENCODED_PASSWORD)
				.build());
		account.withdraw();
		em.flush();
		em.clear();
		Account rejoin = Account.builder()
				.email("reuse@example.com")
				.password(RAW_ENCODED_PASSWORD)
				.build();

		assertThatThrownBy(() -> accountRepository.saveAndFlush(rejoin))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("existsByEmail·findByEmail 이 저장된 계정을 찾는다")
	void email_조회() {
		accountRepository.saveAndFlush(Account.builder()
				.email("find@example.com")
				.password(RAW_ENCODED_PASSWORD)
				.build());
		em.clear();

		assertThat(accountRepository.existsByEmail("find@example.com")).isTrue();
		assertThat(accountRepository.existsByEmail("missing@example.com")).isFalse();
		assertThat(accountRepository.findByEmail("find@example.com")).isPresent();
	}

	@Test
	@DisplayName("AccountReader 는 없는 id 조회 시 BusinessException(AU001) 을 던진다")
	void 없는_계정_조회() {
		assertThatThrownBy(() -> accountReader.getById(999_999L))
				.isInstanceOf(BusinessException.class)
				.extracting(e -> ((BusinessException) e).getErrorCode())
				.isEqualTo(ErrorCode.ACCOUNT_NOT_FOUND);
	}

	@Test
	@DisplayName("AccountReader 는 존재하는 계정을 돌려준다")
	void 있는_계정_조회() {
		Long id = accountRepository.saveAndFlush(Account.builder()
				.email("reader@example.com")
				.password(RAW_ENCODED_PASSWORD)
				.build()).getId();

		assertThat(accountReader.getById(id).getEmail()).isEqualTo("reader@example.com");
	}

}
