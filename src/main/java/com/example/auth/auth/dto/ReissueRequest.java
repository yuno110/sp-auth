package com.example.auth.auth.dto;

/**
 * 토큰 재발급 요청. 정본: sp-docs/api-contract.md §2.1, sp-docs/security.md §4.
 *
 * <p>Refresh Token 은 <b>본문으로 온다.</b> 그래서 이 엔드포인트는 무인증이고
 * ({@code SecurityConfig}) 필터가 이 토큰을 보지 않는다 — 검증은 {@code AuthService} 가 한다.
 *
 * <p><b>검증 애노테이션을 두지 않는다.</b> 정본이 재발급에 정한 결과는 200 과 401 뿐이다
 * (sp-docs/api-contract.md §2.1 §8.1) — 400 경로를 정하지 않았다. {@code @NotBlank} 를 붙이면
 * 정본에 없는 400 {@code C001} 이 생긴다. 토큰이 비어 있는 경우는 {@code AuthService} 가
 * 401 {@code A001}("인증이 필요합니다") 로 처리한다 — 제시된 토큰이 없는 것이므로
 * {@code A002}(유효하지 않은 토큰)가 아니다 (§8.1 의 메시지). {@link LoginRequest} 와 같은
 * 이유다.
 */
public record ReissueRequest(String refreshToken) {
}
