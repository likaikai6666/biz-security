package com.security.demo.backend.model;

import lombok.Data;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Positive;

/**
 * App 端公钥交换请求
 */
@Data
public class ShortTermKeyExchangeRequest {
    @NotBlank(message = "deviceId 不能为空")
    private String deviceId;

    @NotBlank(message = "App 公钥不能为空")
    private String clientPublicKey; // PEM格式公钥

    @NotBlank(message = "签名不能为空")
    private String signature; // App 对关键信息的签名

    @Positive(message = "时间戳必须为正数")
    private Long timestamp; // 毫秒级时间戳

    @NotBlank(message = "随机字符串不能为空")
    private String nonce;
}
