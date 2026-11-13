package com.example.auth.account.service;

import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.AccountToken;
import com.example.auth.account.entity.TokenPurpose;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.account.repository.AccountTokenRepository;
import com.example.auth.account.support.AccountTokens;
import com.example.auth.global.config.MailExecutorConfig;
import com.example.auth.mail.MailDispatcher;
import com.example.auth.mail.MailSettings;
import com.example.auth.mail.OutgoingMail;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 링크 토큰 발급 작업 — 이메일 인증과 비밀번호 재설정의 메일 (sp-docs/requirements/member.md §11.5).
 *
 * <p><b>작업은 부른 스레드가 아니라 발송 실행기({@link MailExecutorConfig})에서 돈다.</b> 부르는 쪽은 작업을 넘기기만
 * 하고 DB 일을 하지 않는다 — 재발송·재설정 요청의 응답 시간이 계정 유무로 갈리지 않게 하려는 것이다
 * (sp-docs/requirements/member.md §11.3, sp-docs/security.md §12).
 *
 * <p>작업은 자기 트랜잭션에서 아래 순서로 돈다 (sp-docs/plan/phase2-auth-member.md AU-15).
 * <ol>
 *   <li>계정을 찾는다</li>
 *   <li>그 목적의 보낼 조건을 본다 — 안 되면 토큰도 메일도 없다 (sp-docs/requirements/member.md §11.2·§11.3)</li>
 *   <li>계정 id·목적의 발송 상한을 본다 — 넘으면 발급·발송하지 않고 WARN ({@link AccountTokenSendLimit})</li>
 *   <li>같은 계정·목적의 앞 토큰을 지운다 — 마지막 메일의 링크만 산다 (sp-docs/requirements/member.md §11.1)</li>
 *   <li>새 토큰을 넣는다. 저장은 해시뿐이다 ({@link AccountTokens})</li>
 *   <li><b>그 트랜잭션이 커밋된 뒤</b> 메일을 보낸다 ({@link MailDispatcher#sendAfterCommit})</li>
 * </ol>
 *
 * <p><b>메일은 계정에 저장된 주소로 보낸다.</b> 요청에 실린 표기로 보내지 않는다 — 계정 조회는 콜레이션으로
 * 비교하므로 다른 표기로도 같은 계정을 찾는다 (sp-docs/requirements/member.md §11.3).
 *
 * <p><b>링크의 기준 주소는 설정({@code mail.frontend-base-url})에서만 온다.</b> 요청의 {@code Host}·{@code Origin}
 * 을 읽지 않는다 (sp-docs/security.md §12).
 *
 * <p>작업이 실패하면 WARN 한 줄을 남기고 끝낸다. 그 줄에는 계정 id·목적·예외의 종류만 싣는다 — 토큰·링크·주소는
 * 싣지 않는다 (sp-docs/security.md §12). 다시 시도하지 않는다 (sp-docs/requirements/member.md §11.5).
 */
@Component
public class AccountTokenIssuer {

	/** 인증 링크의 수명 (sp-docs/requirements/member.md §11.1). */
	static final Duration EMAIL_VERIFICATION_LIFETIME = Duration.ofHours(24);

	/** 재설정 링크의 수명 (sp-docs/requirements/member.md §11.1). */
	static final Duration PASSWORD_RESET_LIFETIME = Duration.ofMinutes(30);

	/** 화면의 인증 경로. 토큰은 fragment 에 싣는다 (sp-docs/requirements/member.md §11.5). */
	static final String VERIFY_EMAIL_PATH = "/verify-email#token=";

	/** 화면의 재설정 경로. 토큰은 fragment 에 싣는다 (sp-docs/requirements/member.md §11.5). */
	static final String RESET_PASSWORD_PATH = "/reset-password#token=";

	private static final Logger log = LoggerFactory.getLogger(AccountTokenIssuer.class);

	private final AccountRepository accountRepository;

	private final AccountTokenRepository accountTokenRepository;

	private final AccountTokenSendLimit sendLimit;

	private final MailDispatcher mailDispatcher;

	private final MailSettings mailSettings;

	private final Executor mailExecutor;

	private final TransactionTemplate transaction;

	private final Clock clock;

	public AccountTokenIssuer(
			AccountRepository accountRepository,
			AccountTokenRepository accountTokenRepository,
			AccountTokenSendLimit sendLimit,
			MailDispatcher mailDispatcher,
			MailSettings mailSettings,
			@Qualifier(MailExecutorConfig.MAIL_EXECUTOR) Executor mailExecutor,
			PlatformTransactionManager transactionManager,
			Clock clock) {

		this.accountRepository = accountRepository;
		this.accountTokenRepository = accountTokenRepository;
		this.sendLimit = sendLimit;
		this.mailDispatcher = mailDispatcher;
		this.mailSettings = mailSettings;
		this.mailExecutor = mailExecutor;
		this.transaction = new TransactionTemplate(transactionManager);
		this.clock = clock;
	}

	/**
	 * 재발송·재설정 요청의 발급. 요청 스레드에서 부른다 — 작업을 실행기에 넘기기만 하고 DB 일을 하지 않는다.
	 * 계정은 작업이 이 이메일로 찾는다.
	 *
	 * <p>실행기의 대기열이 차 있으면 작업이 버려지고 실행기가 WARN 을 남긴다 ({@link MailExecutorConfig}).
	 */
	public void request(TokenPurpose purpose, String email) {
		this.mailExecutor.execute(() -> run(purpose, () -> this.accountRepository.findByEmail(email)));
	}

	/**
	 * 가입의 발급. 계정 INSERT 의 트랜잭션 안에서 부른다 — <b>그 트랜잭션이 커밋된 뒤</b> 작업을 실행기에 넘긴다.
	 * 되돌려지면 넘기지 않는다 (sp-docs/requirements/member.md §11.2·§11.5). 계정은 작업이 이 id 로 찾는다.
	 *
	 * @throws IllegalStateException 트랜잭션 동기화가 없을 때 — 아무것도 걸지 않는다. 커밋 뒤를 지킬 수 없는
	 *     호출을 바로 넘기는 것으로 바꾸지 않는다
	 */
	public void requestAfterCommit(TokenPurpose purpose, Long accountId) {
		if (!TransactionSynchronizationManager.isSynchronizationActive()) {
			throw new IllegalStateException("가입의 발급은 계정 INSERT 가 커밋된 뒤에 넘긴다 — 트랜잭션 안에서 건다 "
					+ "(sp-docs/requirements/member.md §11.2).");
		}
		TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
			@Override
			public void afterCommit() {
				AccountTokenIssuer.this.mailExecutor.execute(
						() -> run(purpose, () -> AccountTokenIssuer.this.accountRepository.findById(accountId)));
			}
		});
	}

	/** 실행기에서 도는 작업. 실패를 WARN 으로 남기고 삼킨다 — 실행기 밖으로 던지면 로그 규칙 밖에서 스택이 남는다. */
	private void run(TokenPurpose purpose, Supplier<Optional<Account>> findAccount) {
		AtomicReference<Long> accountId = new AtomicReference<>();
		try {
			this.transaction.executeWithoutResult(status -> issue(purpose, findAccount, accountId));
		} catch (RuntimeException e) {
			// 예외 객체를 로그 인자로 넘기지 않는다 — 넘기면 메시지와 스택이 함께 남는다
			log.warn("account token issue failed: accountId={}, purpose={}, exception={}, cause={}",
					accountId.get(), purpose, e.getClass().getName(),
					NestedExceptionUtils.getMostSpecificCause(e).getClass().getName());
		}
	}

	/** 작업의 트랜잭션 안. {@code foundAccountId} 는 실패의 로그가 쓸 계정 id 를 받는다. */
	private void issue(TokenPurpose purpose, Supplier<Optional<Account>> findAccount,
			AtomicReference<Long> foundAccountId) {

		Optional<Account> found = findAccount.get();
		if (found.isEmpty()) {
			return;
		}
		Account account = found.get();
		Long accountId = account.getId();
		foundAccountId.set(accountId);

		if (!sendable(account, purpose)) {
			return;
		}

		// 상한은 앞 토큰을 지우기 전에 본다 — 넘친 요청이 마지막으로 보낸 링크를 죽이지 않는다
		Optional<Instant> acquired = this.sendLimit.tryAcquire(accountId, purpose);
		if (acquired.isEmpty()) {
			log.warn("account token not issued: send limit reached (accountId={}, purpose={}, limit={} per {})",
					accountId, purpose, AccountTokenSendLimit.LIMIT, AccountTokenSendLimit.WINDOW);
			return;
		}
		Instant acquiredAt = acquired.get();
		TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
			@Override
			public void afterCompletion(int status) {
				if (status != STATUS_COMMITTED) {
					AccountTokenIssuer.this.sendLimit.release(accountId, purpose, acquiredAt);
				}
			}
		});

		// 이 삭제는 영속성 컨텍스트를 비운다. account 는 그 뒤 읽기만 한다
		this.accountTokenRepository.deleteByAccountIdAndPurpose(accountId, purpose);
		String token = AccountTokens.generate();
		this.accountTokenRepository.save(
				AccountToken.issue(accountId, purpose, AccountTokens.hash(token), lifetime(purpose), this.clock));

		this.mailDispatcher.sendAfterCommit(mail(account, purpose, token));
	}

	/**
	 * 보낼 조건. 인증은 활성이고 아직 인증되지 않은 계정, 재설정은 활성인 계정이다 — 인증 여부를 보지 않는다
	 * (sp-docs/requirements/member.md §11.2·§11.3).
	 */
	private static boolean sendable(Account account, TokenPurpose purpose) {
		return switch (purpose) {
			case EMAIL_VERIFICATION -> account.isActive() && account.getEmailVerifiedAt() == null;
			case PASSWORD_RESET -> account.isActive();
		};
	}

	private static Duration lifetime(TokenPurpose purpose) {
		return switch (purpose) {
			case EMAIL_VERIFICATION -> EMAIL_VERIFICATION_LIFETIME;
			case PASSWORD_RESET -> PASSWORD_RESET_LIFETIME;
		};
	}

	/**
	 * 메일 한 통. 받는 주소는 계정에 저장된 주소다. 인증 메일은 「가입하지 않았다면 이 메일을 무시하세요」 를 적는다
	 * — 남이 그 주소로 만든 계정을 주인이 인증해 주지 않게 한다 (sp-docs/requirements/member.md §11.2).
	 */
	private OutgoingMail mail(Account account, TokenPurpose purpose, String token) {
		String baseUrl = this.mailSettings.frontendBaseUrl();
		return switch (purpose) {
			case EMAIL_VERIFICATION -> new OutgoingMail(account.getId(), purpose.name(), account.getEmail(),
					"이메일 인증",
					"아래 링크를 열어 이메일 인증을 마치세요.\n\n"
							+ baseUrl + VERIFY_EMAIL_PATH + token + "\n\n"
							+ "가입하지 않았다면 이 메일을 무시하세요.\n");
			case PASSWORD_RESET -> new OutgoingMail(account.getId(), purpose.name(), account.getEmail(),
					"비밀번호 재설정",
					"아래 링크를 열어 새 비밀번호를 정하세요.\n\n"
							+ baseUrl + RESET_PASSWORD_PATH + token + "\n\n"
							+ "비밀번호 재설정을 요청하지 않았다면 이 메일을 무시하세요.\n");
		};
	}

}
