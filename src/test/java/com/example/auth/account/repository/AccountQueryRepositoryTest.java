package com.example.auth.account.repository;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.account.dto.AccountSearchCondition;
import com.example.auth.account.dto.AccountSortType;
import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.Role;
import com.example.auth.global.config.JpaConfig;
import com.example.auth.global.config.QuerydslConfig;
import jakarta.persistence.EntityManager;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

/**
 * AU-20 — 계정 목록의 조건·정렬·페이징 (sp-docs/api-contract.md §2.5·§7.1). {@code replace = NONE} 의 이유는
 * {@code AccountRepositoryTest} 에 있다. 각 테스트는 롤백된다. seed ADMIN 이 있으므로 내용을 보는 단언은
 * {@value #DOMAIN} 조건을 건다.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({JpaConfig.class, QuerydslConfig.class, AccountQueryRepository.class})
@ActiveProfiles("test")
class AccountQueryRepositoryTest {

	private static final String DOMAIN = "@query.test";

	@Autowired
	private AccountQueryRepository accountQueryRepository;

	@Autowired
	private AccountRepository accountRepository;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private EntityManager entityManager;

	/**
	 * 같은 {@code created_at} 이 셋이면 {@code id DESC} 로 갈린다 — 정렬 키의 끝에 {@code id} 가 있다(§7.1). 페이지를 나눠
	 * 읽어도 행이 겹치거나 빠지지 않는다.
	 */
	@Test
	@DisplayName("latest 는 created_at DESC, 같으면 id DESC 이고 페이지 사이에 겹침·빠짐이 없다")
	void 최신순_동률() {
		Long a = 계정("a", Role.USER);
		Long b = 계정("b", Role.USER);
		Long c = 계정("c", Role.USER);
		Long d = 계정("d", Role.USER);
		LocalDateTime same = LocalDateTime.of(2026, 11, 1, 0, 0, 0);
		생성시각(a, same);
		생성시각(b, same);
		생성시각(c, same);
		생성시각(d, same.minusDays(1));

		assertThat(ids(조건(0, 50, AccountSortType.latest))).containsExactly(c, b, a, d);
		assertThat(ids(조건(0, 2, AccountSortType.latest))).containsExactly(c, b);
		assertThat(ids(조건(1, 2, AccountSortType.latest))).containsExactly(a, d);
	}

	@Test
	@DisplayName("email 은 email ASC, id ASC 다")
	void 이메일순() {
		Long b = 계정("b", Role.USER);
		Long a = 계정("a", Role.USER);
		Long c = 계정("c", Role.USER);

		assertThat(ids(조건(0, 50, AccountSortType.email))).containsExactly(a, b, c);
	}

	@Test
	@DisplayName("totalElements·totalPages 가 조건에 걸린 전체다")
	void 개수() {
		계정("a", Role.USER);
		계정("b", Role.USER);
		계정("c", Role.USER);

		Page<Account> page = this.accountQueryRepository.search(조건(0, 2, AccountSortType.latest));

		assertThat(page.getContent()).hasSize(2);
		assertThat(page.getTotalElements()).isEqualTo(3);
		assertThat(page.getTotalPages()).isEqualTo(2);
	}

	/** {@code LIKE '%값%'} 의 값은 글자 그대로다 — {@code _} 가 아무 글자와 맞으면 부분 일치가 아니다. */
	@Test
	@DisplayName("email 의 _·% 는 와일드카드가 아니라 글자다")
	void 와일드카드_글자() {
		Long underscore = 계정("x_y", Role.USER);
		계정("xzy", Role.USER);

		assertThat(ids(new AccountSearchCondition(0, 50, AccountSortType.email, "x_y", null, null)))
				.containsExactly(underscore);
		assertThat(ids(new AccountSearchCondition(0, 50, AccountSortType.email, "%" + DOMAIN, null, null)))
				.isEmpty();
	}

	@Test
	@DisplayName("role·deleted 조건은 AND 로 걸리고, 없으면 둘 다다")
	void 역할_탈퇴() {
		Long user = 계정("user", Role.USER);
		Long admin = 계정("admin", Role.ADMIN);
		Long gone = 계정("gone", Role.ADMIN);
		this.jdbcTemplate.update("update account set deleted = true where id = ?", gone);
		this.entityManager.clear();

		assertThat(ids(new AccountSearchCondition(0, 50, AccountSortType.email, DOMAIN, Role.ADMIN, null)))
				.containsExactly(admin, gone);
		assertThat(ids(new AccountSearchCondition(0, 50, AccountSortType.email, DOMAIN, null, true)))
				.containsExactly(gone);
		assertThat(ids(new AccountSearchCondition(0, 50, AccountSortType.email, DOMAIN, null, false)))
				.containsExactly(admin, user);
		assertThat(ids(new AccountSearchCondition(0, 50, AccountSortType.email, DOMAIN, Role.ADMIN, false)))
				.containsExactly(admin);
		assertThat(ids(new AccountSearchCondition(0, 50, AccountSortType.email, DOMAIN, null, null)))
				.containsExactly(admin, gone, user);
	}

	@Test
	@DisplayName("조건의 정규화 — size 는 50 으로 절삭, 공백만인 email 은 없음, 기본값은 0·20·latest")
	void 조건_정규화() {
		assertThat(AccountSearchCondition.of(null, 51, null, null, null, null).size()).isEqualTo(50);
		assertThat(AccountSearchCondition.of(null, 50, null, null, null, null).size()).isEqualTo(50);
		assertThat(AccountSearchCondition.of(null, 1, null, null, null, null).size()).isEqualTo(1);
		assertThat(AccountSearchCondition.of(null, null, null, " \t ", null, null).email()).isNull();
		assertThat(AccountSearchCondition.of(null, null, null, "", null, null).email()).isNull();
		assertThat(AccountSearchCondition.of(null, null, null, " a ", null, null).email()).isEqualTo(" a ");
		AccountSearchCondition defaults = AccountSearchCondition.of(null, null, null, null, null, null);
		assertThat(defaults.page()).isZero();
		assertThat(defaults.size()).isEqualTo(20);
		assertThat(defaults.sort()).isEqualTo(AccountSortType.latest);
	}

	private Long 계정(String local, Role role) {
		return this.accountRepository.saveAndFlush(Account.builder()
				.email(local + DOMAIN)
				.password("x".repeat(60))
				.role(role)
				.build()).getId();
	}

	private void 생성시각(Long id, LocalDateTime createdAt) {
		this.jdbcTemplate.update("update account set created_at = ? where id = ?", Timestamp.valueOf(createdAt), id);
		this.entityManager.clear();
	}

	private static AccountSearchCondition 조건(int page, int size, AccountSortType sort) {
		return new AccountSearchCondition(page, size, sort, DOMAIN, null, null);
	}

	private List<Long> ids(AccountSearchCondition condition) {
		return this.accountQueryRepository.search(condition).getContent().stream().map(Account::getId).toList();
	}

}
