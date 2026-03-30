package com.security.demo.backend.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Component
public class AuthenticationLogger {

    // 监听 Token 认证成功事件
    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        // 判断是否是 JWT Token 认证
        if (event.getAuthentication() instanceof JwtAuthenticationToken jwtAuth) {
            HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
            String path = request.getRequestURI();
            String username = jwtAuth.getName(); // JWT 中的 subject（通常是 clientId 或用户名）
            String scopes = jwtAuth.getAuthorities().toString(); // Token 包含的权限

            System.out.printf("[Token 验证成功] 路径: %s, 客户端: %s, 权限: %s%n", path, username, scopes);
        }
    }

    // 监听 Token 认证失败事件（如 Token 无效、过期等）
    @EventListener
    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        String path = request.getRequestURI();
        String error = event.getException().getMessage();

        System.out.printf("[Token 验证失败] 路径: %s, 原因: %s%n", path, error);
    }
}