package com.example.auth.account.dto;

/**
 * 중복 확인 응답. 정본: sp-docs/api-contract.md §2.3 — {@code { "available": boolean }}.
 *
 * <p><b>쓸 수 있으면 {@code true}</b>다. {@code duplicated} 같은 부정형을 쓰지 않는다 — 이중
 * 부정이 생겨 호출 측이 뒤집어 읽는다. member 의 {@code check-nickname} 도 같은 형태를 쓴다.
 *
 * <p><b>탈퇴한 계정의 이메일은 {@code false} 다.</b> 행이 남아 재사용되지 않기 때문이다
 * (sp-docs/requirements/member.md §3 규칙 1). 닉네임만 탈퇴 후 {@code true} 가 될 수 있다.
 */
public record CheckResponse(boolean available) { }
