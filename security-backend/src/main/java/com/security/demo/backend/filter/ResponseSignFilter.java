package com.security.demo.backend.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.demo.backend.aws.CreateKmsAsymmetricKeyUtil;
import com.security.demo.backend.aws.KmsSignature;
import com.security.demo.backend.util.SignatureUtils;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

@Component
public class ResponseSignFilter implements Filter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String deviceId = httpRequest.getHeader("X-Device-Id");
        String appId = httpRequest.getHeader("X-App-Id");
        String path = httpRequest.getRequestURI();

        // 1. 使用 Spring 提供的 ContentCachingResponseWrapper 包装响应（更可靠）
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(httpResponse);

        try {
            // 2. 执行过滤器链，让响应体写入 wrapper
            chain.doFilter(request, responseWrapper);

            // 3. 判断是否需要签名（仅对 /api/security/ 下的接口签名，排除长期密钥交换接口）
            boolean needSign = path.startsWith("/api/security/")
                    && !"/api/security/long-term-key/exchange".equals(path);

            // 4. 仅对成功响应（200 OK）签名
            if (needSign && responseWrapper.getStatus() == HttpServletResponse.SC_OK) {
                try {
                    // 5. 从 wrapper 中获取响应体（注意编码）
                    byte[] responseBytes = responseWrapper.getContentAsByteArray();
                    String responseBody = new String(responseBytes, StandardCharsets.UTF_8);
                    if (responseBody.isEmpty()) {
                        System.out.println("响应体为空，跳过签名");
                        return;
                    }

                    // 6. 生成签名参数
                    String timestamp = String.valueOf(System.currentTimeMillis());
                    String nonce = UUID.randomUUID().toString();
                    String signAlg = "RSA-PSS-SHA256";
                    String dataDigest = SignatureUtils.calculateBodyDigest(objectMapper.readTree(responseBody));
                    String signData = SignatureUtils.buildSignData(
                            appId, timestamp, nonce, signAlg, deviceId, dataDigest
                    );

                    // 7. 生成签名（确保密钥存在）
                    String secretKey = CreateKmsAsymmetricKeyUtil.getLongTermSignKeyName(deviceId);
                    if (secretKey == null || secretKey.isEmpty()) {
                        throw new IllegalArgumentException("未找到设备对应的签名密钥: " + deviceId);
                    }
                    String signature = KmsSignature.signData(signData, secretKey);

                    // 8. 关键：向包装类设置响应头（而非原始 response）
                    responseWrapper.setHeader("X-App-Id", appId);
                    responseWrapper.setHeader("X-Data-Digest", dataDigest);
                    responseWrapper.setHeader("X-Timestamp", timestamp);
                    responseWrapper.setHeader("X-Nonce", nonce);
                    responseWrapper.setHeader("X-Signature", signature);
                    responseWrapper.setHeader("X-Sign-Alg", signAlg);

                    // 打印调试信息
                    System.out.println("===== 响应签名信息 =====");
                    System.out.println("签名字符串: " + signData);
                    System.out.println("X-Signature: " + signature);
                    System.out.println("X-Data-Digest: " + dataDigest);
                    System.out.println("=======================");

                } catch (Exception e) {
                    System.err.println("响应签名生成失败: " + e.getMessage());
                    e.printStackTrace(); // 打印完整堆栈，便于排查
                    // 可选：签名失败是否返回 500 错误
                    // responseWrapper.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                }
            }

        } finally {
            // 9. 关键：将包装类的响应（包含头和体）复制到原始响应
            // 必须调用此方法，否则前端收不到响应体和头
            responseWrapper.copyBodyToResponse();
        }
    }
}