package com.security.demo.backend.filter;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * 包装 HttpServletRequest，实现请求体的重复读取
 */
public class RepeatableReadRequestWrapper extends HttpServletRequestWrapper {

    // 缓存请求体内容
    private final byte[] bodyBytes;

    public RepeatableReadRequestWrapper(HttpServletRequest request) throws IOException {
        super(request);
        // 读取原始请求体并缓存
        bodyBytes = readRequestBody(request);
    }

    /**
     * 读取原始请求体内容
     */
    private byte[] readRequestBody(HttpServletRequest request) throws IOException {
        try (InputStream inputStream = request.getInputStream();
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[1024];
            int length;
            while ((length = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, length);
            }
            return outputStream.toByteArray();
        }
    }

    /**
     * 重写 getInputStream()，返回缓存的请求体
     */
    @Override
    public ServletInputStream getInputStream() throws IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bodyBytes);
        return new ServletInputStream() {
            @Override
            public int read() throws IOException {
                return byteArrayInputStream.read();
            }

            @Override
            public boolean isFinished() {
                return byteArrayInputStream.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                // 无需实现
            }
        };
    }

    /**
     * 重写 getReader()，方便按字符读取请求体
     */
    @Override
    public BufferedReader getReader() throws IOException {
        return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
    }

    /**
     * 获取请求体字符串（UTF-8 编码）
     */
    public String getBody() {
        return new String(bodyBytes, StandardCharsets.UTF_8);
    }
}
