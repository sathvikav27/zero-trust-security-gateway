package com.sathvika.zerotrust.auth.dto;

public record LoginResponse(
    String accessToken,
    String tokenType,
    long expiresIn
) {
}