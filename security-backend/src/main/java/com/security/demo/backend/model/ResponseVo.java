package com.security.demo.backend.model;

public class ResponseVo<T> {
    private int code;       // 状态码（0=成功，非0=失败）
    private String message; // 响应消息
    private T data;         // 响应数据（加密后的结果）

    // 构造方法
    public ResponseVo(int code, String message, T data) {
        this.code = code;
        this.message = message;
        this.data = data;
    }

    // Getter（前端需要解析这些字段）
    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public T getData() {
        return data;
    }
}
