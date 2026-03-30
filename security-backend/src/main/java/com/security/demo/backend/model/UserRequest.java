package com.security.demo.backend.model;

import lombok.Data;

/**
 * 长期公钥交换请求
 */
@Data
public class UserRequest {
    private String username;
    private String passwordHash;
    private String salt;
}
