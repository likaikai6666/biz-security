package com.security.demo.backend.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.demo.backend.service.SecurityService;
import com.security.demo.backend.util.SignatureUtils;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/**
 * 签名验证过滤器：验证请求中的签名是否有效
 */
@Component
public class SignatureVerificationFilter implements Filter { // 这里实现的是 jakarta.servlet.Filter

    private SecurityService securityService;

    public SignatureVerificationFilter(SecurityService securityService) {
        this.securityService = securityService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.setCharacterEncoding(StandardCharsets.UTF_8.name());
        // 仅处理 POST 请求（GET 请求无 Body）
        if ("POST".equalsIgnoreCase(httpRequest.getMethod())) {

            String path = httpRequest.getRequestURI();
            if ("/api/security/long-term-key/exchange".equals(path) || !path.startsWith("/api/security/")) {
                chain.doFilter(request, response);
                return;
            }
            String appId = httpRequest.getHeader("X-App-Id");
            String deviceId = httpRequest.getHeader("X-Device-Id");
            String timestamp = httpRequest.getHeader("X-Timestamp");
            String nonce = httpRequest.getHeader("X-Nonce");
            String signAlg = httpRequest.getHeader("X-Sign-Alg");
            String signature = httpRequest.getHeader("X-Signature");
            System.out.println("timestamp: " + timestamp);
            // 包装请求，实现 Body 重复读取
            RepeatableReadRequestWrapper wrappedRequest = new RepeatableReadRequestWrapper(httpRequest);
            // 获取完整请求体内容
            String requestBody = wrappedRequest.getBody();
            System.out.println("POST 请求体：" + requestBody);

            try {

                if (appId == null || deviceId == null || timestamp == null || nonce == null ||
                        signature == null) {
                    httpResponse.setStatus(HttpStatus.BAD_REQUEST.value());
                    httpResponse.getWriter().write("签名参数不完整（appId、deviceId、timestamp、nonce、signature、text 均为必填）");
                    return;
                }

                // 3. 校验时间戳（防止重放攻击，5分钟内有效）
                long requestTime;
                try {
                    requestTime = Long.parseLong(timestamp);
                } catch (NumberFormatException e) {
                    httpResponse.setStatus(HttpStatus.BAD_REQUEST.value());
                    httpResponse.getWriter().write("无效的时间戳（必须为数字）");
                    return;
                }
                long now = System.currentTimeMillis();
                if (now - requestTime > TimeUnit.MINUTES.toMillis(5)) {
                    httpResponse.setStatus(HttpStatus.BAD_REQUEST.value());
                    httpResponse.getWriter().write("请求已过期（超过5分钟）");
                    return;
                }

                // 4. 获取客户端长期公钥（PEM格式，与前端交换后存储）
                String publicKeyPem = securityService.getLongTermPublicKey(deviceId);

                if (publicKeyPem == null) {
                    httpResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
                    httpResponse.getWriter().write("未找到设备[" + deviceId + "]的长期公钥，请先完成密钥交换");
                    return;
                }

                // 5. 构建待签名字符串（与前端SignatureUtils.buildSignData逻辑一致）
                // 注意：此处需根据实际请求体生成bodyDigest，若请求参数是form-data，需调整获取方式
                // 简化示例：假设encryptedText是请求体核心数据，直接计算其摘要
                String bodyDigest = SignatureUtils.calculateBodyDigest(new ObjectMapper().readTree(requestBody));
                String signData = SignatureUtils.buildSignData(appId, timestamp, nonce, signAlg, deviceId, bodyDigest);
                // 6. 调用工具类验证签名（使用SHA256withRSA算法）
                boolean verifySuccess = SignatureUtils.verifyWithClientPublicKey(signData, signature,publicKeyPem);
                if (!verifySuccess) {
                    httpResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
                    httpResponse.getWriter().write("签名验证失败（数据可能被篡改或签名错误）");
                    return;
                }
                // 7. 签名验证通过，继续处理请求
                chain.doFilter(wrappedRequest, response);

            } catch (Exception e) {
                httpResponse.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                httpResponse.getWriter().write("签名验证异常：" + e.getMessage());
            }
        } else {
            // 非 POST 请求直接放行
            chain.doFilter(request, response);
        }

    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }
}