package com.example.auth.global.common;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import java.time.LocalDateTime;
import lombok.Getter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

// 정본: sp-docs/domain-model.md §1.1
// 세 서비스가 각각 갖는 복제 대상이다 (sp-docs/conventions.md §7.1).
// 변경 시 세 서비스를 함께 고친다.
//
// 감사 값을 채우는 @EnableJpaAuditing 은 global/config/JpaConfig 에 있다.
@Getter
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseTimeEntity {

	@CreatedDate
	@Column(updatable = false)
	private LocalDateTime createdAt;

	@LastModifiedDate
	private LocalDateTime updatedAt;

}
