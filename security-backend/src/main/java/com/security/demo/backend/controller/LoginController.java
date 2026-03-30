package com.security.demo.backend.controller;

import com.security.demo.backend.model.UserRequest;
import com.security.demo.backend.model.UserResponse;
import com.security.demo.backend.service.LoginService;
import io.swagger.v3.oas.annotations.Operation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.NoSuchAlgorithmException;
import java.util.UUID;

@RestController
@RequestMapping("/api/user")
public class LoginController {
    @Autowired
    private LoginService loginService;

    @PostMapping("/login")
    @Operation(summary = "登录", description = "登录")
    public ResponseEntity<UserResponse> login(@RequestBody UserRequest request) throws NoSuchAlgorithmException {
        String token = loginService.login(request);
        UserResponse response = new UserResponse();
        response.setAccessToken(token);
        response.setDeviceId(UUID.randomUUID().toString());
        return ResponseEntity.ok(response);
    }
}