package com.sqisoft.sef.modules.user.dto.request;

// 요청 DTO(입력 전용) — 응답에 직렬화되지 않으므로 @JsonIgnore 불필요(오탐이면 안 됨).
public class VerifyPasswordRequest {
    private String password;
}
