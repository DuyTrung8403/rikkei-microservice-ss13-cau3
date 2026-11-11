package com.rikkei.microservice.identityservice;

import com.rikkei.microservice.identityservice.dto.RegisterRequest;
import com.rikkei.microservice.identityservice.dto.UserResponse;
import com.rikkei.microservice.identityservice.entity.User;
import com.rikkei.microservice.identityservice.repository.UserRepository;
import com.rikkei.microservice.identityservice.security.JwtUtil;
import com.rikkei.microservice.identityservice.service.AuthService;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class IdentityServiceTests {

    @Autowired
    private AuthService authService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Bài 1: Đăng ký thành công, password được băm BCrypt")
    void testRegister_Success() {
        RegisterRequest request = RegisterRequest.builder()
                .username("john_doe")
                .password("Password123@")
                .role("ADMIN")
                .build();

        UserResponse response = authService.register(request);

        assertNotNull(response.getId());
        assertEquals("john_doe", response.getUsername());
        assertEquals("ADMIN", response.getRole());

        User savedUser = userRepository.findByUsername("john_doe").orElse(null);
        assertNotNull(savedUser);
        assertTrue(passwordEncoder.matches("Password123@", savedUser.getPassword()));
    }

    @Test
    @DisplayName("Bài 2: Sinh JWT Token với subject là username và custom claim role")
    void testGenerateToken_Claims() {
        User user = User.builder()
                .id("test-id-123")
                .username("test_user")
                .password("hashed_password")
                .role("ROLE_MANAGER")
                .build();

        String token = jwtUtil.generateToken(user);
        assertNotNull(token);
        assertFalse(token.isEmpty());

        Claims claims = jwtUtil.extractAllClaims(token);
        assertEquals("test_user", claims.getSubject(), "Subject (sub) claim phải là username");
        assertEquals("ROLE_MANAGER", claims.get("role"), "Role claim phải khớp role của user");
        assertNotNull(claims.getExpiration(), "Token phải có thời gian hết hạn");
    }
}
