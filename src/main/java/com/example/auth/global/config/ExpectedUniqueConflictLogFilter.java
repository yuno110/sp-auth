package com.example.auth.global.config;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.turbo.TurboFilter;
import ch.qos.logback.core.spi.FilterReply;
import java.util.Locale;
import org.slf4j.Marker;

/**
 * 가입의 UNIQUE 충돌에 Hibernate 가 남기는 ERROR 줄만 버린다 (sp-docs/conventions.md §8.1 의 표의 auth 행).
 * {@code src/main/resources/logback-spring.xml} 이 로거 컨텍스트에 건다 — 프로파일을 가리지 않는다
 * (sp-docs/tech-stack.md §4.8).
 *
 * <p><b>버리는 것</b>은 {@code org.hibernate.engine.jdbc.spi.SqlExceptionHelper} 의 ERROR 중 {@code uk_account_email} 이 든
 * 줄(대소문자 무시, 부분 일치)이다. {@code AccountService} 의 가입이 그 충돌을 잡아 409 {@code AU002} 로 바꾼다
 * (sp-docs/api-contract.md §2.3). 그 줄에는 중복 값으로 사용자가 고른 이메일이 실린다. 같은 충돌의 WARN
 * {@code SQL Error: …} 줄, 로거의 수준, 다른 제약의 위반과 다른 SQL 오류의 ERROR 는 그대로다 — 이유는 §8.1 의 규칙 표다.
 *
 * <p><b>부분 일치다.</b> H2 는 프로젝트의 테스트 URL 에서 {@code "public.uk_account_email_INDEX_4 ON …"} 로 냈다 (2026-11-25
 * AU-25 실측). MySQL 은 {@code Duplicate entry '…' for key 'account.uk_account_email'} 모양으로 낼 것으로 본다 (§8.1 의 추정 —
 * 실 MySQL 은 재지 않았다). 대소문자는 DB 와 설정에 따라 다르다.
 *
 * <p><b>문면이 {@code null} 인 호출은 판정하지 않는다({@link FilterReply#NEUTRAL}).</b> logback 은 {@code isErrorEnabled()}
 * 같은 수준 검사에서도 TurboFilter 를 문면 없이 부른다. Hibernate 의 {@code logExceptions} 는 그 검사가 거짓이면 WARN 도
 * 남기지 않으므로, 거기서 버리면 WARN 과 다른 ERROR 가 모두 사라진다 (§8.1 의 「로거의 수준을 바꾸지 않는다」 행).
 *
 * <p><b>제약을 더하려면 정본이 먼저다</b> (§8.1). 이름은 sp-docs/domain-model.md §2.3 의 이름 그대로다. 필터 클래스는 서비스마다
 * 각자 쓴다 — 공유 모듈을 만들지 않는다 (sp-docs/conventions.md §7.2).
 */
public class ExpectedUniqueConflictLogFilter extends TurboFilter {

	static final String SQL_EXCEPTION_HELPER = "org.hibernate.engine.jdbc.spi.SqlExceptionHelper";

	/** 가입이 잡아 409 {@code AU002} 로 바꾸는 충돌의 제약 — 소문자로 두고 문면을 소문자로 바꿔 맞춘다. */
	static final String EXPECTED_CONFLICT_CONSTRAINT = "uk_account_email";

	@Override
	public FilterReply decide(Marker marker, Logger logger, Level level, String format, Object[] params,
			Throwable t) {
		if (format == null || level != Level.ERROR || !SQL_EXCEPTION_HELPER.equals(logger.getName())) {
			return FilterReply.NEUTRAL;
		}
		return format.toLowerCase(Locale.ROOT).contains(EXPECTED_CONFLICT_CONSTRAINT)
				? FilterReply.DENY
				: FilterReply.NEUTRAL;
	}

}
