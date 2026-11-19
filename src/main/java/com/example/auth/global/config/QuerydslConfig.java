package com.example.auth.global.config;

import com.querydsl.jpa.impl.JPAQueryFactory;
import jakarta.persistence.EntityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

// 동적 조건의 조회를 QueryDSL 로 조합한다 (sp-docs/conventions.md §1.1, sp-docs/api-contract.md §2.5).
// auth 의 첫 사용처는 AU-20 의 계정 목록이다.
@Configuration
public class QuerydslConfig {

	@Bean
	public JPAQueryFactory jpaQueryFactory(EntityManager entityManager) {
		return new JPAQueryFactory(entityManager);
	}

}
