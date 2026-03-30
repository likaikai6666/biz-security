package com.security.demo.backend.model;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * 服务端公钥交换响应
 */
@AllArgsConstructor
@Data
public class LongTermKeyExchangeResponse {

    private String serverEncryptPublicKey;
    private String serverSignPublicKey;

}
