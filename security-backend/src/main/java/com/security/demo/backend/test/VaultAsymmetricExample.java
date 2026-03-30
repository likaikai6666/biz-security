package com.security.demo.backend.test;

import com.bettercloud.vault.SslConfig;
import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.response.LogicalResponse;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class VaultAsymmetricExample {
    // 配置参数（请根据实际环境修改）
    private static final String VAULT_ADDR = "http://127.0.0.1:8200";
    private static final String ROOT_TOKEN = "hvs.gulQJLsEcRmXakplga5sn4he";
    private static final String KEY_NAME = "rsa-key-8"; // 明确使用RSA密钥
    private static final String TRANSIT_PATH = "transit";

    // 路径定义
    private static final String keyManagementPath = TRANSIT_PATH + "/keys/" + KEY_NAME;
    private static final String encryptPath = TRANSIT_PATH + "/encrypt/" + KEY_NAME;
    private static final String decryptPath = TRANSIT_PATH + "/decrypt/" + KEY_NAME;
    private static final String signPath = TRANSIT_PATH + "/sign/" + KEY_NAME;
    private static final String verifyPath = TRANSIT_PATH + "/verify/" + KEY_NAME;

    public static void main(String[] args) {
        try {
            // 初始化Vault客户端
            VaultConfig config = new VaultConfig()
                    .address(VAULT_ADDR)
                    .engineVersion(1)
                    .token(ROOT_TOKEN)
                    .sslConfig(new SslConfig().verify(false)) // 测试用，生产环境启用SSL验证
                    .build();
            Vault vault = new Vault(config);
            System.out.println("Vault 客户端初始化成功");

            // 先删除旧密钥（若存在）
            deleteOldKey(vault);

            // 创建RSA非对称密钥（支持加密和签名）
            createRsaKeyWithSdk(vault);
            System.out.println("RSA密钥 " + KEY_NAME + " 创建成功");

            // 获取密钥详情（验证是否为RSA类型）
            getKeyDetails(vault);

            // 加密示例（RSA非对称加密）
            String plaintext = "test-encrypt-content";
            String ciphertext = encryptData(vault, plaintext);
            System.out.println("加密结果: " + ciphertext);

            // 解密示例
            String decrypted = decryptData(vault, ciphertext);
            System.out.println("解密结果: " + decrypted + "（与原文一致：" + plaintext.equals(decrypted) + "）");

            // 签名示例
            String dataToSign = "data-to-sign-123";
            String signature = signData(vault, dataToSign);
            System.out.println("签名结果: " + signature);

            // 验证签名
            boolean verifyResult = verifySignature(vault, dataToSign, signature);
            System.out.println("签名验证结果: " + (verifyResult ? "验证通过" : "验证失败"));

            // 篡改数据验证
            boolean fakeVerifyResult = verifySignature(vault, dataToSign + "-fake", signature);
            System.out.println("篡改数据后验证结果: " + (fakeVerifyResult ? "验证通过" : "验证失败"));

        } catch (VaultException e) {
            System.err.println("Vault 错误: " + e.getMessage() + "，状态码: " + e.getHttpStatusCode());
        } catch (Exception e) {
            System.err.println("系统错误: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 删除旧密钥（若存在）
     */
    private static void deleteOldKey(Vault vault) {
        try {
            vault.logical().delete(keyManagementPath);
            System.out.println("旧密钥 " + KEY_NAME + " 已删除（若存在）");
        } catch (VaultException e) {
            if (e.getHttpStatusCode() != 404) {
//                System.err.println("删除旧密钥失败: " + e.getMessage());
                // 若删除失败，手动通过Vault CLI删除（参考之前的步骤）
            }
        }
    }

    /**
     * 创建RSA非对称密钥（支持加密和签名）
     */
    private static void createRsaKeyWithSdk(Vault vault) throws VaultException {
        Map<String, Object> createParams = new HashMap<>();
        createParams.put("type", "rsa-2048");           // RSA 2048位算法（支持签名）
        createParams.put("exportable", true);            // 允许导出公钥（可选）
        createParams.put("deletion_allowed", true);      // 允许删除密钥
        createParams.put("auto_rotate_period", 3600);    // 自动轮换周期（1小时）
        // 移除AES特有的参数（convergent_encryption、context等）

        LogicalResponse response = vault.logical().write(keyManagementPath, createParams);

        if (response.getRestResponse().getStatus() < 200 || response.getRestResponse().getStatus() >= 300) {
            throw new VaultException("创建RSA密钥失败，响应状态: " + response.getRestResponse().getStatus(),
                    response.getRestResponse().getStatus());
        }
    }

    /**
     * 加密数据（RSA非对称加密）
     */
    public static String encryptData(Vault vault, String plaintext) throws VaultException {
        Map<String, Object> encryptParams = new HashMap<>();
        // 明文Base64编码
        String base64Plaintext = Base64.getEncoder().encodeToString(plaintext.getBytes(StandardCharsets.UTF_8));
        encryptParams.put("plaintext", base64Plaintext);

        LogicalResponse response = vault.logical().write(encryptPath, encryptParams);
        if (response == null || response.getData() == null) {
            throw new RuntimeException("加密请求失败，Vault无响应");
        }

        String ciphertext = response.getData().get("ciphertext");
        if (ciphertext == null || ciphertext.isEmpty()) {
            throw new RuntimeException("Vault返回空密文，请检查参数");
        }
        return ciphertext;
    }

    /**
     * 解密数据（RSA非对称解密）
     */
    public static String decryptData(Vault vault, String ciphertext) throws VaultException {
        Map<String, Object> decryptParams = new HashMap<>();
        decryptParams.put("ciphertext", ciphertext);

        LogicalResponse response = vault.logical().write(decryptPath, decryptParams);
        if (response == null || response.getData() == null) {
            throw new RuntimeException("解密请求失败，Vault无响应");
        }

        String base64Plaintext = response.getData().get("plaintext");
        if (base64Plaintext == null || base64Plaintext.isEmpty()) {
            throw new RuntimeException("Vault返回空明文，请检查密文");
        }

        return new String(Base64.getDecoder().decode(base64Plaintext), StandardCharsets.UTF_8);
    }

    /**
     * 签名数据（使用RSA私钥）
     */
    public static String signData(Vault vault, String data) throws VaultException {
        Map<String, Object> signParams = new HashMap<>();
        // 待签名数据Base64编码
        String base64Data = Base64.getEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8));
        signParams.put("input", base64Data);
        signParams.put("hash_algorithm", "sha2-256"); // 指定哈希算法

        LogicalResponse response = vault.logical().write(signPath, signParams);
        if (response == null || response.getData() == null) {
            throw new RuntimeException("签名请求失败，Vault无响应");
        }

        String signature = response.getData().get("signature");
        if (signature == null || signature.isEmpty()) {
            throw new RuntimeException("Vault返回空签名，请检查密钥是否为RSA类型");
        }
        return signature;
    }

    /**
     * 验证签名（使用RSA公钥）
     */
    public static boolean verifySignature(Vault vault, String data, String signature) throws VaultException {
        Map<String, Object> verifyParams = new HashMap<>();
        String base64Data = Base64.getEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8));
        verifyParams.put("input", base64Data);
        verifyParams.put("signature", signature);
        verifyParams.put("hash_algorithm", "sha2-256"); // 与签名时一致

        LogicalResponse response = vault.logical().write(verifyPath, verifyParams);
        if (response == null || response.getData() == null) {
            throw new RuntimeException("验签请求失败，Vault无响应");
        }

        // 处理Vault返回的验证结果（兼容String和Boolean类型）
        Object validObj = response.getData().get("valid");
        if (validObj instanceof String) {
            return "true".equalsIgnoreCase((String) validObj);
        } else if (validObj instanceof Boolean) {
            return (Boolean) validObj;
        } else {
            return false;
        }
    }

    /**
     * 获取密钥详情（验证是否为RSA类型）
     */
    private static void getKeyDetails(Vault vault) throws VaultException {
        LogicalResponse response = vault.logical().read(keyManagementPath);
        if (response == null || response.getData() == null) {
            System.out.println("密钥详情: 未获取到详情");
            return;
        }
        System.out.println("密钥详情: " + response.getData());
        // 检查是否支持签名（RSA密钥的supports_signing应为true）
        System.out.println("是否支持签名: " + response.getData().get("supports_signing"));
    }
}