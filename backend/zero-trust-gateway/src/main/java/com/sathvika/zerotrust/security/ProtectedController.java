
package com.sathvika.zerotrust.security;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/secure")
public class ProtectedController {

    @GetMapping("/me")
    public Map<String, Object> getCurrentUser(Authentication authentication) {
        return Map.of(
                "message", "Access granted",
                "email", authentication.getName(),
                "authorities", authentication.getAuthorities()
                        .stream()
                        .map(authority -> authority.getAuthority())
                        .toList()
        );
    }
}