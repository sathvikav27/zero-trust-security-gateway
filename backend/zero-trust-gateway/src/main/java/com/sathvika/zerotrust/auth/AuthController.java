package com.sathvika.zerotrust.auth;

import com.sathvika.zerotrust.auth.dto.LoginRequest;
import com.sathvika.zerotrust.auth.dto.LoginResponse;
import com.sathvika.zerotrust.user.User;
import com.sathvika.zerotrust.user.UserService;
import com.sathvika.zerotrust.user.dto.RegisterRequest;
import com.sathvika.zerotrust.user.dto.UserResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;
    private final long expirationMs;

    public AuthController(
            UserService userService,
            JwtService jwtService,
            @Value("${JWT_EXPIRATION_MS:900000}") long expirationMs) {
        this.userService = userService;
        this.jwtService = jwtService;
        this.expirationMs = expirationMs;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public UserResponse register(
            @Valid @RequestBody RegisterRequest request) {
        return userService.register(request);
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        User user = userService.authenticate(request.email(), request.password());

        String token = jwtService.generateToken(user.getEmail());

        return new LoginResponse(
                token,
                "Bearer",
                expirationMs / 1000
        );
    }
}