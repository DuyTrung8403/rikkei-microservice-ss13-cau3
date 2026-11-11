package com.rikkei.microservice.identityservice;

import com.rikkei.microservice.identityservice.dto.RegisterRequest;
import com.rikkei.microservice.identityservice.dto.UserResponse;
import com.rikkei.microservice.identityservice.entity.User;
import com.rikkei.microservice.identityservice.repository.UserRepository;
import com.rikkei.microservice.identityservice.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class RegisterServiceIntegrationTest {

    @Autowired
    private AuthService authService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Đăng ký thành công: trả về thông tin user không kèm password, DB lưu mật khẩu đã băm BCrypt")
    void testRegister_Success() {
        RegisterRequest request = RegisterRequest.builder()
                .username("john_doe")
                .password("Password123@")
                .role("USER")
                .build();

        UserResponse response = authService.register(request);

        // Kiểm tra kết quả trả về
        assertNotNull(response.getId());
        assertEquals("john_doe", response.getUsername());
        assertEquals("USER", response.getRole());

        // Kiểm tra trong cơ sở dữ liệu
        User savedUser = userRepository.findByUsername("john_doe").orElse(null);
        assertNotNull(savedUser, "User phải được lưu vào PostgreSQL database");
        assertNotEquals("Password123@", savedUser.getPassword(), "Mật khẩu trong DB không được là plain-text");
        assertTrue(savedUser.getPassword().startsWith("$2a$") || savedUser.getPassword().startsWith("$2b$"),
                "Mật khẩu phải được băm theo chuẩn BCrypt");
        assertTrue(passwordEncoder.matches("Password123@", savedUser.getPassword()),
                "BCrypt password encoder phải xác thực khớp với mật khẩu gốc");
    }
}
