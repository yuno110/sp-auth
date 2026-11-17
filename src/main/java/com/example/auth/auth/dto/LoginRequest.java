package com.example.auth.auth.dto;

/**
 * 로그인 요청. 정본: sp-docs/api-contract.md §2.1 §9.1, sp-docs/security.md §4.
 *
 * <p><b>검증 애노테이션을 두지 않는다.</b> 정본은 로그인에 400 을 쓰지 않는다 — 누락·빈 값·형식이 틀린
 * 값도 401 {@code AU003} 이다 (sp-docs/api-contract.md §2.1 「로그인의 응답」 표·§8.4). 생성 쪽의 형식
 * 규칙(sp-docs/requirements/member.md §2)을 여기에 복제하면 정본에 없는 응답이 생기고, 게다가
 * <b>"형식이 틀린 비밀번호"와 "일치하지 않는 비밀번호"가 응답에서 갈린다.</b> 중복 확인
 * 엔드포인트에는 정본이 같은 규칙을 적용하라고 명시했지만(§2.3) 로그인에는 그런 문장이 없다.
 *
 * <p>자격증명이 비어 있는 경우도 {@code AuthService} 가 불일치와 <b>같은 401</b> 로 처리한다.
 */
public record LoginRequest(String email, String password) {
}
