package com.security.demo.backend.aws;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

public class ClientUtil {
    private final static KmsClient kmsClient;

    static {
        // 配置区域（替换为你的区域）
        Region region = Region.EU_WEST_1;
        kmsClient = KmsClient.builder()
                .region(region)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
    }

    public static KmsClient getKmsClient() {
        return kmsClient;
    }
}
