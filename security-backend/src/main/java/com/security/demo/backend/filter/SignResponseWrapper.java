package com.security.demo.backend.filter;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;

public class SignResponseWrapper extends HttpServletResponseWrapper {
    private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    private PrintWriter writer;

    public SignResponseWrapper(HttpServletResponse response) {
        super(response);
    }

    // 重写输出流，将响应数据写入字节数组（而非直接发送给客户端）
    @Override
    public PrintWriter getWriter() {
        if (writer == null) {
            writer = new PrintWriter(outputStream);
        }
        return writer;
    }

    // 获取捕获的响应体字节数组
    public byte[] getResponseBytes() {
        if (writer != null) {
            writer.flush(); // 确保数据写入输出流
        }
        return outputStream.toByteArray();
    }

    // 获取响应体字符串（UTF-8编码）
    public String getResponseBody() {
        return new String(getResponseBytes(), java.nio.charset.StandardCharsets.UTF_8);
    }
}
