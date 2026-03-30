package com.security.demo.backend.service;

import com.security.demo.backend.model.UserRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;

@Service
@RequiredArgsConstructor
public class LoginService {

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    /**
     * 验证客户端传递的哈希和盐值
     */
    public String login(UserRequest request) throws NoSuchAlgorithmException {

        return generateToken(request.getUsername());
    }


    /**
     * 生成JWT Token（简化示例）
     */
    private String generateToken(String username) {
        // 实际项目中使用JWT库生成（如jjwt）
        return "jwt_token_" + username + "_" + System.currentTimeMillis();
    }

}
