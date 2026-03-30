package com.security.demo.backend.config;

import com.security.demo.backend.model.ApiResponse;
import com.security.demo.backend.model.BusinessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 全局异常处理器
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    // 处理参数校验失败（如@Valid注解触发）
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Void>> handleValidationException(
            MethodArgumentNotValidException e) {
        BindingResult result = e.getBindingResult();
        StringBuilder errorMsg = new StringBuilder();
        for (FieldError error : result.getFieldErrors()) {
            errorMsg.append(error.getField()).append(":").append(error.getDefaultMessage()).append(";");
        }
        return ResponseEntity.badRequest()
                .body(ApiResponse.fail(400, errorMsg.toString()));
    }

    // 处理业务异常（如签名无效、请求过期）
    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ApiResponse<Void>> handleBusinessException(BusinessException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.fail(e.getCode(), e.getMessage()));
    }

    // 处理其他未知异常
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleUnknownException(Exception e) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.fail(500, "服务器内部错误"));
    }
}
