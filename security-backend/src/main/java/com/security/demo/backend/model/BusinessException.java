package com.security.demo.backend.model;

public class BusinessException extends RuntimeException {
    private int code;

    public BusinessException(int code, String message) {
        super(message);
        this.code = code;
    }

    public BusinessException(String message) {
        this(400, message); // 默认400错误码
    }

    public int getCode() {
        return code;
    }
}
