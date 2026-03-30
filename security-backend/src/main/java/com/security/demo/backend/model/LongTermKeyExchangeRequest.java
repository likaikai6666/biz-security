package com.security.demo.backend.model;

import lombok.Data;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Positive;

/**
 * 长期公钥交换请求
 */
@Data
public class LongTermKeyExchangeRequest {
    private String deviceId;

    @NotBlank(message = "客户端类型不能为空")
    private String clientType;

    @NotBlank(message = "客户端公钥不能为空")
    private String clientPublicKey;


}
