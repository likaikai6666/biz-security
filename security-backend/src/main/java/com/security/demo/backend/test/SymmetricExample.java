package com.security.demo.backend.test;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SymmetricExample {
    private static final String KEY_ID = "98848a25-d01a-4142-be50-342ba995c0e4";

    private static final KmsClient kmsClient = KmsClient.builder()
            .region(Region.EU_WEST_1) // 与密钥所在区域一致
            .credentialsProvider(DefaultCredentialsProvider.create())
            .build();

    public static void main(String[] args) {
        try {
            System.out.println("使用的 KMS 密钥 ID: " + KEY_ID);

            // 1. 加密数据（对称密钥无需指定算法）
            String plaintext = "Hello, AWS KMS (Symmetric Key)!";
            String encryptedData = encryptData(KEY_ID, plaintext);
            System.out.println("加密后的数据 (Base64): " + encryptedData);

            // 2. 解密数据
            String decryptedText = decryptData(KEY_ID, encryptedData);
            System.out.println("解密后的数据: " + decryptedText);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            kmsClient.close();
        }
    }

    /**
     * 对称密钥加密（无需指定算法，默认使用 SYMMETRIC_DEFAULT）
     */
    private static String encryptData(String keyId, String plaintext) {
        SdkBytes plaintextBytes = SdkBytes.fromString(plaintext, StandardCharsets.UTF_8);
        EncryptRequest request = EncryptRequest.builder()
                .keyId(keyId)
                .plaintext(plaintextBytes)
                .build();
        EncryptResponse response = kmsClient.encrypt(request);
        return Base64.getEncoder().encodeToString(response.ciphertextBlob().asByteArray());
    }

    /**
     * 对称密钥解密（无需指定算法）
     */
    private static String decryptData(String keyId, String encryptedData) {
        byte[] ciphertext = Base64.getDecoder().decode(encryptedData);
        SdkBytes ciphertextBytes = SdkBytes.fromByteArray(ciphertext);
        DecryptRequest request = DecryptRequest.builder()
                .keyId(keyId)
                .ciphertextBlob(ciphertextBytes)
                .build();
        DecryptResponse response = kmsClient.decrypt(request);
        return response.plaintext().asString(StandardCharsets.UTF_8);
    }
}