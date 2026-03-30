package com.security.demo.backend.test;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AsymmetricExample {
    // 替换为你创建的非对称密钥 ID
    private static final String KEY_ID = "alias/kyle-asymmetric-key-2025-11-12_17_02_21";

    private static final KmsClient kmsClient = KmsClient.builder()
            .region(Region.EU_WEST_1) // 与密钥区域一致
            .credentialsProvider(DefaultCredentialsProvider.create())
            .build();

    public static void main(String[] args) {
        try {
            System.out.println("使用的非对称 KMS 密钥 ID: " + KEY_ID);

            // 1. 加密数据（非对称加密，使用公钥）
//            String plaintext = "Hello, AWS KMS (Asymmetric Key)!";
//            String encryptedData = encryptData(KEY_ID, plaintext);
//            System.out.println("加密后的数据 (Base64): " + encryptedData);
//
//            // 2. 解密数据（非对称解密，使用私钥）
//            String decryptedText = decryptData(KEY_ID, encryptedData);
//            System.out.println("解密后的数据: " + decryptedText);

            // 3. 签名数据（使用私钥）
            String dataToSign = "Data to sign with asymmetric key";
            String signature = signData(KEY_ID, dataToSign);
            System.out.println("签名结果 (Base64): " + signature);

            // 4. 验证签名（使用公钥）
            boolean isSignatureValid = verifySignature(KEY_ID, dataToSign, signature);
            System.out.println("签名验证结果: " + (isSignatureValid ? "通过" : "失败"));

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            kmsClient.close();
        }
    }

    /**
     * 非对称加密（使用 RSA 公钥）
     */
    private static String encryptData(String keyId, String plaintext) {
        SdkBytes plaintextBytes = SdkBytes.fromString(plaintext, StandardCharsets.UTF_8);

        EncryptRequest request = EncryptRequest.builder()
                .keyId(keyId)
                .plaintext(plaintextBytes)
                // 非对称加密算法（必须与 RSA 密钥匹配）
                .encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
                .build();

        EncryptResponse response = kmsClient.encrypt(request);
        return Base64.getEncoder().encodeToString(response.ciphertextBlob().asByteArray());
    }

    /**
     * 非对称解密（使用 RSA 私钥）
     */
    private static String decryptData(String keyId, String encryptedData) {
        byte[] ciphertext = Base64.getDecoder().decode(encryptedData);
        SdkBytes ciphertextBytes = SdkBytes.fromByteArray(ciphertext);

        DecryptRequest request = DecryptRequest.builder()
                .keyId(keyId)
                .ciphertextBlob(ciphertextBytes)
                // 与加密算法一致
                .encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
                .build();

        DecryptResponse response = kmsClient.decrypt(request);
        return response.plaintext().asString(StandardCharsets.UTF_8);
    }

    /**
     * 非对称签名（使用 RSA 私钥）
     */
    private static String signData(String keyId, String data) {
        SdkBytes dataBytes = SdkBytes.fromString(data, StandardCharsets.UTF_8);

        SignRequest request = SignRequest.builder()
                .keyId(keyId)
                .message(dataBytes)
                // 非对称签名算法
                .signingAlgorithm(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256)
                .build();

        SignResponse response = kmsClient.sign(request);
        return Base64.getEncoder().encodeToString(response.signature().asByteArray());
    }

    /**
     * 验证签名（使用 RSA 公钥）
     */
    private static boolean verifySignature(String keyId, String data, String signature) {
        SdkBytes dataBytes = SdkBytes.fromString(data, StandardCharsets.UTF_8);
        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        VerifyRequest request = VerifyRequest.builder()
                .keyId(keyId)
                .message(dataBytes)
                .signature(SdkBytes.fromByteArray(signatureBytes))
                // 与签名算法一致
                .signingAlgorithm(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256)
                .build();

        VerifyResponse response = kmsClient.verify(request);
        return response.signatureValid();
    }
}