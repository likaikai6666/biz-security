package com.security.demo.backend.aws;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class KmsSignature {

    // 签名算法（需与 KMS 密钥的算法匹配，如 RSA 对应 RSASSA_PSS_SHA_256）
    private static final String SIGNING_ALGORITHM = "ECDSA_SHA_256";

    /**
     * 使用 KMS 私钥对数据进行签名
     *
     * @param data 待签名的数据（字符串）
     * @return 签名结果（Base64 编码）
     */
    public static String signData(String data, String signKmsKyeId) {
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);

        // 2. 构建 ECDSA 签名请求（KMS 会自动使用密钥支持的算法）
        SignRequest signRequest = SignRequest.builder()
                .keyId(signKmsKyeId)
                .message(SdkBytes.fromByteArray(dataBytes))
                .signingAlgorithm(SIGNING_ALGORITHM) // 明确指定 ECDSA
                .build();

        SignResponse signResponse = ClientUtil.getKmsClient().sign(signRequest);

        DescribeKeyRequest describeRequest = DescribeKeyRequest.builder()
                .keyId(signKmsKyeId)
                .build();
        DescribeKeyResponse describeResponse = ClientUtil.getKmsClient().describeKey(describeRequest);
        System.out.println("KMS密钥签名参数: " + describeResponse.keyMetadata().signingAlgorithms());
        KeySpec keySpec = describeResponse.keyMetadata().keySpec();
        System.out.println("KMS 密钥曲线: " + keySpec);
        // 3. 签名结果仍以 Base64 编码返回
        return Base64.getEncoder().encodeToString(signResponse.signature().asByteArray());
    }

    /**
     * 使用 KMS 公钥验证签名
     *
     * @param data      原始数据（字符串）
     * @param signature 待验证的签名（Base64 编码）
     * @return 验证结果（true/false）
     */
    public static boolean verifySignature(String data, String signature, String signKmsKyeId) {
        System.out.println("verifySignature.data:"+data);
        System.out.println("verifySignature.signature:"+signature);
        // 1. 解码签名
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        // 2. 原始数据转换为字节数组
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);

        // 3. 构建验证请求
        VerifyRequest verifyRequest = VerifyRequest.builder()
                .keyId(signKmsKyeId)
                .message(SdkBytes.fromByteArray(dataBytes))
                .signature(SdkBytes.fromByteArray(signatureBytes))
                .signingAlgorithm(SIGNING_ALGORITHM)
                .build();

        // 4. 调用 KMS 验证接口
        VerifyResponse verifyResponse = ClientUtil.getKmsClient().verify(verifyRequest);
        // 返回验证结果
        return verifyResponse.signatureValid();
    }
}
