package com.sathvika.zerotrust.user.dto;

import com.sathvika.zerotrust.user.Role;
import java.time.Instant;

public record UserResponse(
    Long id,
    String fullName,
    String email,
    Role role,
    Instant createdAt
) {
}