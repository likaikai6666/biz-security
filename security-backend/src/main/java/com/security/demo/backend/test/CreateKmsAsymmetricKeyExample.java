package com.security.demo.backend.test;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class CreateKmsAsymmetricKeyExample {

    public static void main(String[] args) {
        // 配置区域（替换为你的区域）
        Region region = Region.EU_WEST_1;
        KmsClient kmsClient = KmsClient.builder()
                .region(region)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();

        try {
            // 1. 创建非对称密钥
            CreateKeyRequest createKeyRequest = CreateKeyRequest.builder()
                    .keySpec(KeySpec.RSA_2048)
                    .keyUsage(KeyUsageType.ENCRYPT_DECRYPT)
                    .keyUsage(KeyUsageType.SIGN_VERIFY)
                    .description("Key with custom alias")
                    .build();

            CreateKeyResponse createResponse = kmsClient.createKey(createKeyRequest);
            String keyId = createResponse.keyMetadata().keyId();
            System.out.println("密钥创建成功，ID: " + keyId);

            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH_mm_ss");
            String currentTime = LocalDateTime.now().format(formatter);


            String aliasName = "alias/kyle-asymmetric-key-" + currentTime;
            CreateAliasRequest createAliasRequest = CreateAliasRequest.builder()
                    .aliasName(aliasName)
                    .targetKeyId(keyId)
                    .build();

            kmsClient.createAlias(createAliasRequest);
            System.out.println("已为密钥添加别名: " + aliasName);

        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
            e.printStackTrace();
        } finally {
            kmsClient.close();
        }
    }
}