package com.sathvika.zerotrust.security;

import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
public class AdminController {


@GetMapping("/dashboard")
public Map<String, Object> dashboard(
        Authentication authentication) {

    return Map.of(
        "message", "Admin access granted",
        "email", authentication.getName(),
        "role", "ADMIN"
    );
}


}
