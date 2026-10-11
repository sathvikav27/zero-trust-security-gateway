
package com.sathvika.zerotrust;

import com.sathvika.zerotrust.auth.JwtService;
import com.sathvika.zerotrust.user.User;
import com.sathvika.zerotrust.user.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.Optional;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class ZeroTrustGatewayApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private JwtService jwtService;

    @MockBean
    private UserRepository userRepository;

    @Test
    void contextLoads() {
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
    void healthEndpointIsPublic() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk());
    }

    @Test
    void invalidTokenIsRejected() throws Exception {
        when(jwtService.validateAndParseToken("invalid-token"))
                .thenThrow(new JwtException("Invalid token"));

        mockMvc.perform(get("/api/secure/me")
                        .header(HttpHeaders.AUTHORIZATION,
                                "Bearer invalid-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void validUserTokenCanAccessProtectedEndpoint() throws Exception {
        Claims claims = Jwts.claims()
                .subject("user@example.com")
                .build();

        User user = mock(User.class);
        when(user.getEmail()).thenReturn("user@example.com");
        when(user.isEnabled()).thenReturn(true);

        Object userRole = Arrays.stream(
                        User.class.getMethod("getRole")
                                .getReturnType()
                                .getEnumConstants())
                .filter(role -> ((Enum<?>) role).name().equals("USER"))
                .findFirst()
                .orElseThrow(() ->
                        new IllegalStateException("USER role not found"));

        doReturn(userRole).when(user).getRole();

        when(jwtService.validateAndParseToken("valid-user-token"))
                .thenReturn(claims);
        when(userRepository.findByEmail("user@example.com"))
                .thenReturn(Optional.of(user));

        mockMvc.perform(get("/api/secure/me")
                        .header(HttpHeaders.AUTHORIZATION,
                                "Bearer valid-user-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email")
                        .value("user@example.com"));
    }

    @Test
    void regularUserCannotAccessAdminEndpoint() throws Exception {
        Claims claims = Jwts.claims()
                .subject("user@example.com")
                .build();

        User user = mock(User.class);
        when(user.getEmail()).thenReturn("user@example.com");
        when(user.isEnabled()).thenReturn(true);

        Object userRole = Arrays.stream(
                        User.class.getMethod("getRole")
                                .getReturnType()
                                .getEnumConstants())
                .filter(role -> ((Enum<?>) role).name().equals("USER"))
                .findFirst()
                .orElseThrow(() ->
                        new IllegalStateException("USER role not found"));

        doReturn(userRole).when(user).getRole();

        when(jwtService.validateAndParseToken("valid-user-token"))
                .thenReturn(claims);
        when(userRepository.findByEmail("user@example.com"))
                .thenReturn(Optional.of(user));

        mockMvc.perform(get("/api/admin/dashboard")
                        .header(HttpHeaders.AUTHORIZATION,
                                "Bearer valid-user-token"))
                .andExpect(status().isForbidden());
    }
}
