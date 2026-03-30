package com.security.demo.backend.aws;

import com.security.demo.backend.model.AwsKmsResult;
import software.amazon.awssdk.services.kms.model.*;

import java.util.Base64;

public class CreateKmsAsymmetricKeyUtil {
    public static String getLongTermEncryptKeyName(String deviceId) {
        return "alias/kyle-asymmetric-long-term-1-" + deviceId;
    }
    public static String getLongTermSignKeyName(String deviceId) {
        return "alias/kyle-sign-long-term-1-" + deviceId;
    }
    public static AwsKmsResult createAsymmetricKey(KeyUsageType keyUsage, String aliasName) {
        AwsKmsResult awsKmsResult = new AwsKmsResult();
        try {
            // 1. 先检查别名是否已存在（幂等核心：避免重复创建）
            String existingKeyId = getKeyIdByAlias(aliasName);
            if (existingKeyId != null) {
                System.out.println("别名已存在，直接使用现有密钥: " + aliasName);
                // 2. 存在则查询现有密钥的公钥并返回
                GetPublicKeyRequest getPublicKeyRequest = GetPublicKeyRequest.builder()
                        .keyId(aliasName) // 使用别名查询
                        .build();
                GetPublicKeyResponse publicKeyResponse = ClientUtil.getKmsClient().getPublicKey(getPublicKeyRequest);
                byte[] publicKeyBytes = publicKeyResponse.publicKey().asByteArray();

                awsKmsResult.setAliasName(aliasName);
                awsKmsResult.setType(keyUsage.name());
                awsKmsResult.setPublicKey(Base64.getEncoder().encodeToString(publicKeyBytes));
                return awsKmsResult;
            }
            KeySpec keySpec = KeySpec.RSA_2048;
            if(keyUsage == KeyUsageType.SIGN_VERIFY){
                keySpec = KeySpec.ECC_NIST_P256;
            }
            // 3. 别名不存在，创建新密钥
            CreateKeyRequest createKeyRequest = CreateKeyRequest.builder()
                    .keySpec(keySpec)
                    .keyUsage(keyUsage)
                    .description(aliasName)
                    .build();

            CreateKeyResponse createResponse = ClientUtil.getKmsClient().createKey(createKeyRequest);
            String keyId = createResponse.keyMetadata().keyId();
            System.out.println("密钥创建成功，ID: " + keyId);

            // 4. 为新密钥创建别名（若创建别名失败，需清理已创建的密钥）
            try {
                CreateAliasRequest createAliasRequest = CreateAliasRequest.builder()
                        .aliasName(aliasName)
                        .targetKeyId(keyId)
                        .build();
                ClientUtil.getKmsClient().createAlias(createAliasRequest);
                System.out.println("已为密钥添加别名: " + aliasName);
            } catch (Exception e) {
                System.err.println("创建别名失败，开始清理已创建的密钥: " + keyId);
                // 清理：删除未成功关联别名的密钥，避免资源残留
                ClientUtil.getKmsClient().scheduleKeyDeletion(ScheduleKeyDeletionRequest.builder()
                        .keyId(keyId)
                        .pendingWindowInDays(7) // 7天内可恢复，按需调整
                        .build());
                throw new RuntimeException("创建别名失败，已触发密钥清理: " + e.getMessage(), e);
            }

            // 5. 获取新密钥的公钥并返回
            GetPublicKeyRequest getPublicKeyRequest = GetPublicKeyRequest.builder()
                    .keyId(aliasName)
                    .build();
            GetPublicKeyResponse publicKeyResponse = ClientUtil.getKmsClient().getPublicKey(getPublicKeyRequest);
            byte[] publicKeyBytes = publicKeyResponse.publicKey().asByteArray();

            awsKmsResult.setAliasName(aliasName);
            awsKmsResult.setType(keyUsage.name());
            awsKmsResult.setPublicKey(Base64.getEncoder().encodeToString(publicKeyBytes));
            return awsKmsResult;

        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 通过别名查询密钥ID，不存在则返回null
     */
    private static String getKeyIdByAlias(String aliasName) {
        try {
            // 尝试通过别名查询密钥元数据
            DescribeKeyRequest describeKeyRequest = DescribeKeyRequest.builder()
                    .keyId(aliasName)
                    .build();
            DescribeKeyResponse response = ClientUtil.getKmsClient().describeKey(describeKeyRequest);
            return response.keyMetadata().keyId();
        } catch (NotFoundException e) {
            // 别名不存在，返回null
            return null;
        } catch (Exception e) {
            // 其他异常（如权限问题），向上抛出
            throw new RuntimeException("查询别名对应的密钥失败: " + e.getMessage(), e);
        }
    }

    public static boolean doesKeyExist(String keyId) {
        try {
            DescribeKeyRequest request = DescribeKeyRequest.builder()
                    .keyId(keyId)
                    .build();
            ClientUtil.getKmsClient().describeKey(request); // 若不存在会抛出异常
            return true;
        } catch (NotFoundException e) {
            return false;
        }
    }
}