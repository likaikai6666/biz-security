package com.security.demo.backend.test;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AppKeyManager {
    // 生成 RSA 密钥对（长期使用）
    public static KeyPair generateLongTermKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    // 用 App 私钥签名公钥（首次发送时使用）
    public static String signPublicKey(PublicKey publicKey, PrivateKey privateKey, String deviceId) throws Exception {
        // 待签名内容：公钥 + 设备ID + 时间戳（防重放）
        String content = Base64.getEncoder().encodeToString(publicKey.getEncoded())
                + "|" + deviceId
                + "|" + System.currentTimeMillis();

        // 用私钥签名
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(content.getBytes());
        byte[] signBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signBytes) + "|" + content; // 签名+原始内容
    }
}
