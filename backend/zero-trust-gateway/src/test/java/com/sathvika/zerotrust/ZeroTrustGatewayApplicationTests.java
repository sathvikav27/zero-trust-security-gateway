package com.sathvika.zerotrust;

import com.sathvika.zerotrust.auth.JwtService;
import com.sathvika.zerotrust.user.Role;
import com.sathvika.zerotrust.user.User;
import com.sathvika.zerotrust.user.UserRepository;
import com.sathvika.zerotrust.user.UserService;
import com.sathvika.zerotrust.user.dto.UserResponse;
import io.jsonwebtoken.Jwts;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ZeroTrustGatewayApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtService jwtService;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private UserService userService;

    @Test
    void contextLoads() {
    }

    @Test
    void healthEndpointIsAvailable() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    void protectedEndpointRejectsRequestWithoutToken() throws Exception {
        mockMvc.perform(get("/api/secure/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void adminEndpointRejectsRequestWithoutToken() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void invalidTokenIsRejected() throws Exception {
        mockMvc.perform(get("/api/secure/me")
                        .header("Authorization", "Bearer invalid.token.value"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void validTokenCanAccessSecureEndpoint() throws Exception {
        User user = mock(User.class);

        when(user.getEmail()).thenReturn("test@example.com");
        when(user.getRole()).thenReturn(Role.USER);
        when(user.isEnabled()).thenReturn(true);

        when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(user));

        String token = jwtService.generateToken("test@example.com");

        mockMvc.perform(get("/api/secure/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void userCannotAccessAdminEndpoint() throws Exception {
        User user = mock(User.class);

        when(user.getEmail()).thenReturn("test@example.com");
        when(user.getRole()).thenReturn(Role.USER);
        when(user.isEnabled()).thenReturn(true);

        when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(user));

        String token = jwtService.generateToken("test@example.com");

        mockMvc.perform(get("/api/admin/dashboard")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void registrationCreatesUser() throws Exception {
        UserResponse response = new UserResponse(
                1L,
                "Test User",
                "newuser@example.com",
                Role.USER,
                Instant.parse("2026-01-01T00:00:00Z"));

        when(userService.register(any())).thenReturn(response);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "fullName": "Test User",
                                  "email": "newuser@example.com",
                                  "password": "StrongPassword123"
                                }
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.email").value("newuser@example.com"))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void duplicateEmailReturnsConflict() throws Exception {
        when(userService.register(any()))
                .thenThrow(
                        new com.sathvika.zerotrust.user.EmailAlreadyRegisteredException());

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "fullName": "Test User",
                                  "email": "existing@example.com",
                                  "password": "StrongPassword123"
                                }
                                """))
                .andExpect(status().isConflict());
    }

    @Test
    void invalidRegistrationInputReturnsBadRequest() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "fullName": "",
                                  "email": "not-an-email",
                                  "password": "short"
                                }
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void successfulLoginReturnsBearerToken() throws Exception {
        User user = mock(User.class);

        when(user.getEmail()).thenReturn("newuser@example.com");
        when(userService.authenticate(
                "newuser@example.com", "StrongPassword123"))
                .thenReturn(user);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "newuser@example.com",
                                  "password": "StrongPassword123"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900));
    }

    @Test
    void incorrectPasswordReturnsUnauthorized() throws Exception {
        when(userService.authenticate(
                "newuser@example.com", "WrongPassword123"))
                .thenThrow(
                        new com.sathvika.zerotrust.user.InvalidCredentialsException());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "newuser@example.com",
                                  "password": "WrongPassword123"
                                }
                                """))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unknownEmailReturnsUnauthorized() throws Exception {
        when(userService.authenticate(
                "unknown@example.com", "StrongPassword123"))
                .thenThrow(
                        new com.sathvika.zerotrust.user.InvalidCredentialsException());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "unknown@example.com",
                                  "password": "StrongPassword123"
                                }
                                """))
                .andExpect(status().isUnauthorized());
    }
    @Test
    void expiredTokenIsRejected() throws Exception {
        SecretKey signingKey = (SecretKey)
                ReflectionTestUtils.getField(jwtService, "signingKey");

        Date now = new Date();
        Date issuedAt = new Date(now.getTime() - 120_000);
        Date expiredAt = new Date(now.getTime() - 60_000);

        String expiredToken = Jwts.builder()
                .subject("test@example.com")
                .issuedAt(issuedAt)
                .expiration(expiredAt)
                .signWith(signingKey)
                .compact();

        mockMvc.perform(get("/api/secure/me")
                        .header("Authorization", "Bearer " + expiredToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void disabledUserCannotAccessSecureEndpoint() throws Exception {
        User user = mock(User.class);

        when(user.getEmail()).thenReturn("disabled@example.com");
        when(user.getRole()).thenReturn(Role.USER);
        when(user.isEnabled()).thenReturn(false);

        when(userRepository.findByEmail("disabled@example.com"))
                .thenReturn(Optional.of(user));

        String token = jwtService.generateToken("disabled@example.com");

        mockMvc.perform(get("/api/secure/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void adminCanAccessAdminEndpoint() throws Exception {
        User user = mock(User.class);

        when(user.getEmail()).thenReturn("admin@example.com");
        when(user.getRole()).thenReturn(Role.ADMIN);
        when(user.isEnabled()).thenReturn(true);

        when(userRepository.findByEmail("admin@example.com"))
                .thenReturn(Optional.of(user));

        String token = jwtService.generateToken("admin@example.com");

        mockMvc.perform(get("/api/admin/dashboard")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }
}
