package com.security.demo.backend.model;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * 服务端公钥交换响应
 */
@Data
@AllArgsConstructor
public class ShortTermKeyExchangeResponse {

    private String serverPublicKey; // 服务端长期公钥（PEM格式）

    private String serverSignature; // 服务端对返回信息的签名

    private Long timestamp; // 毫秒级时间戳

    private String nonce;

    public ShortTermKeyExchangeResponse(String serverPublicKey, String serverSignature, String nonce) {
        this.serverPublicKey = serverPublicKey;
        this.serverSignature = serverSignature;
        this.nonce = nonce;
    }
}
