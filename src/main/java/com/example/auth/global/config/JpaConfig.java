package com.example.auth.global.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

// BaseTimeEntity 의 @CreatedDate·@LastModifiedDate 를 채운다
// (sp-docs/domain-model.md §1.1).
@Configuration
@EnableJpaAuditing
public class JpaConfig {

}
