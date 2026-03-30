package com.security.demo.backend.model;

import lombok.Data;

@Data
public class BusinessRequest {
    private String text;       // 前端加密后的文本（原路径参数）
    private String deviceId;   // 设备ID（原请求参数）
}
