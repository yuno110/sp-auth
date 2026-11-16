package com.example.auth.support;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.hibernate.resource.jdbc.spi.StatementInspector;

/**
 * Hibernate 가 준비하는 SQL 을 바꾸지 않고 적어 둔다. 결과로는 드러나지 않는 문장의 모양(예: 잠금 읽기의
 * {@code for update})을 테스트가 SQL 로 보게 한다.
 *
 * <p>컨텍스트에 {@code spring.jpa.properties.hibernate.session_factory.statement_inspector} 로 이 클래스의 이름을 주면
 * 그 컨텍스트의 SessionFactory 가 인스턴스를 만들어 쓴다. 인스턴스를 Hibernate 가 만들므로 기록을 정적으로 두어 테스트가
 * 클래스로 읽게 한다 — 이 설정을 단 컨텍스트들이 기록을 함께 쓰므로, 쓰는 테스트는 관측할 호출 직전에 {@link #clear()}
 * 한다.
 */
public final class RecordingStatementInspector implements StatementInspector {

	private static final List<String> STATEMENTS = new CopyOnWriteArrayList<>();

	@Override
	public String inspect(String sql) {
		STATEMENTS.add(sql);
		return sql;
	}

	/** 적어 둔 SQL 을 비운다. */
	public static void clear() {
		STATEMENTS.clear();
	}

	/** {@link #clear()} 뒤에 준비된 SQL 을 준비된 순서대로 준다. */
	public static List<String> statements() {
		return List.copyOf(STATEMENTS);
	}

}
