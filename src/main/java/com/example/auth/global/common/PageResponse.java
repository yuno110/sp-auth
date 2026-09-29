package com.example.auth.global.common;

import java.util.List;
import org.springframework.data.domain.Page;

// 정본: sp-docs/api-contract.md §7.1
// 세 서비스가 같은 형식을 갖는 복제 대상이다 (sp-docs/conventions.md §7.1).
// 변경 시 세 서비스를 함께 고친다.
//
// 선언 순서가 곧 JSON 키 순서다. §7.1 의 예시와 같은 순서로 둔다.
public record PageResponse<T>(
		List<T> content,
		int page,
		int size,
		long totalElements,
		int totalPages,
		boolean first,
		boolean last
) {

	public static <T> PageResponse<T> of(Page<T> page) {
		return new PageResponse<>(
				page.getContent(),
				page.getNumber(),
				page.getSize(),
				page.getTotalElements(),
				page.getTotalPages(),
				page.isFirst(),
				page.isLast()
		);
	}

}
