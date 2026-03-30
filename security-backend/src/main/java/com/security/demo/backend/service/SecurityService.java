package com.security.demo.backend.service;

import com.security.demo.backend.enums.KeyPrefixEnum;
import com.security.demo.backend.util.ECDHEUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Service
public class SecurityService {
    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    public void setShortTermKey(String deviceId, String privateKey, String serverPublicKey, String clientPublicKey) throws Exception {
        clientPublicKey = trimBase64Margin(clientPublicKey);
        redisTemplate.opsForValue().set(KeyPrefixEnum.SHORT_TERM_PRIVATE.getPrefix() + deviceId, privateKey);
        redisTemplate.opsForValue().set(KeyPrefixEnum.SHORT_TERM_SERVER_PUBLIC.getPrefix() + deviceId, serverPublicKey);
        redisTemplate.opsForValue().set(KeyPrefixEnum.SHORT_TERM_CLIENT_PUBLIC.getPrefix() + deviceId, clientPublicKey);

        String sharedKey = ECDHEUtil.computeSharedSecretAndDeriveAES(privateKey, clientPublicKey);
        System.out.println("Shared Key: " + sharedKey);
        setShortTermSharedKey(deviceId, sharedKey);
    }

    public void setShortTermSharedKey(String deviceId, String encryptedKey) {
        redisTemplate.opsForValue().set(KeyPrefixEnum.SHORT_TERM_SHARED.getPrefix() + deviceId, encryptedKey);
    }

    public void setLongTermPublicKey(String deviceId, String publicKey) {
        redisTemplate.opsForValue().set(KeyPrefixEnum.LONG_TERM.getPrefix() + deviceId, trimBase64Margin(publicKey));
    }

    public String getLongTermPublicKey(String deviceId) {
        return redisTemplate.opsForValue().get(KeyPrefixEnum.LONG_TERM.getPrefix() + deviceId);
    }

    public String getShortTermSharedKey(String deviceId) throws Exception {
        String sharedKey = redisTemplate.opsForValue().get(KeyPrefixEnum.SHORT_TERM_SHARED.getPrefix() + deviceId);
        if (sharedKey == null) {
            String privateKey = redisTemplate.opsForValue().get(KeyPrefixEnum.SHORT_TERM_PRIVATE.getPrefix() + deviceId);
            String serverPublicKey = redisTemplate.opsForValue().get(KeyPrefixEnum.SHORT_TERM_SERVER_PUBLIC.getPrefix() + deviceId);
            String clientPublicKey = redisTemplate.opsForValue().get(KeyPrefixEnum.SHORT_TERM_CLIENT_PUBLIC.getPrefix() + deviceId);
            sharedKey = ECDHEUtil.computeSharedSecretAndDeriveAES(privateKey, clientPublicKey);
            sharedKey = Base64.getEncoder().encodeToString(sharedKey.getBytes(StandardCharsets.UTF_8));
            setShortTermSharedKey(deviceId, sharedKey);
        }
        return redisTemplate.opsForValue().get(KeyPrefixEnum.SHORT_TERM_SHARED.getPrefix() + deviceId);
    }

    private String trimBase64Margin(String clientPublicKeyPem) {
        // 去除换行和空格
        return clientPublicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
    }
}
