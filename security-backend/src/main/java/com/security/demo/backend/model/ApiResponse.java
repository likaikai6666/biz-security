package com.security.demo.backend.model;

/**
 * 通用 API 响应体封装
 * @param <T> 响应数据类型
 */
public class ApiResponse<T> {
    private int code;
    private String message;
    private T data;

    // 成功响应构造器
    public static <T> ApiResponse<T> success(T data) {
        ApiResponse<T> response = new ApiResponse<>();
        response.code = 0;
        response.message = "success";
        response.data = data;
        return response;
    }

    // 失败响应构造器
    public static <T> ApiResponse<T> fail(int code, String message) {
        ApiResponse<T> response = new ApiResponse<>();
        response.code = code;
        response.message = message;
        response.data = null;
        return response;
    }

    // getter/setter
    public int getCode() { return code; }
    public void setCode(int code) { this.code = code; }
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    public T getData() { return data; }
    public void setData(T data) { this.data = data; }
}
