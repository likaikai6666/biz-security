package com.security.demo.backend.util;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class ECDHEUtil {
    private static final String CURVE_NAME = "secp256r1";
    private static final String AES_MODE = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int AES_KEY_LENGTH = 256;
    private static final int KDF_ITERATIONS = 65536;
    private static final byte[] HKDF_SALT = new byte[32];
    // 关键：双方使用相同的固定盐值（实际场景可协商后同步，如随公钥传输）
    private static final byte[] KDF_SALT = "finance-ecdhe-salt-2025".getBytes();


    public static KeyPair generateEphemeralKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(CURVE_NAME);
        keyGen.initialize(ecSpec, new SecureRandom());
        System.out.println("服务端生成新的临时密钥对");
        return keyGen.generateKeyPair();
    }

    public static String exportEphemeralPublicKey(KeyPair ephemeralKeyPair) {
        return Base64.getEncoder().encodeToString(ephemeralKeyPair.getPublic().getEncoded());
    }

    public static String exportEphemeralPrivateKey(KeyPair ephemeralKeyPair) {
        return Base64.getEncoder().encodeToString(ephemeralKeyPair.getPrivate().getEncoded());
    }


    public static String computeSharedSecretAndDeriveAES(
            String serverEphemeralPrivateBase64,
            String clientEphemeralPubBase64) throws Exception {

        // 1. 解析客户端公钥（X.509 格式，正确）
        byte[] clientPubBytes = Base64.getDecoder().decode(clientEphemeralPubBase64);
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(clientPubBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PublicKey clientPublicKey = keyFactory.generatePublic(pubKeySpec);

        // 2. 解析服务端私钥（PKCS#8 格式，修正点）
        byte[] privateKeyBytes = Base64.getDecoder().decode(serverEphemeralPrivateBase64);
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey serverPrivateKey = keyFactory.generatePrivate(privKeySpec);

        // 3. ECDH 计算共享密钥
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(serverPrivateKey); // 初始化私钥
        keyAgreement.doPhase(clientPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        // 4. 使用标准 HKDF 派生 AES 密钥（确保前后端一致）
        SecretKey aesKey = hkdfDerive(
                sharedSecret,
                "ecdhe-aes-gcm".getBytes(), // 上下文信息（与前端一致）
                256 // 密钥长度（256位）
        );

        System.out.println("服务端AES密钥: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));
        return Base64.getEncoder().encodeToString(aesKey.getEncoded());
    }

    private static SecretKey hkdfDerive(byte[] sharedSecret, byte[] info, int keyLength) throws Exception {
        // 1. HKDF-Extract：使用 32 字节全 0 盐值（与前端一致）
        byte[] salt = HKDF_SALT; // 已确认与前端相同（32字节全0）
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(sharedSecret); // 提取伪随机密钥

        // 2. HKDF-Expand：构造 info + 0x01 连续字节流（关键修正）
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        // 合并 info 和 0x01 为一个连续字节数组
        byte[] infoWithTerminator = new byte[info.length + 1];
        System.arraycopy(info, 0, infoWithTerminator, 0, info.length);
        infoWithTerminator[info.length] = 0x01; // 终止符
        // 一次性处理完整字节流
        byte[] okm = mac.doFinal(infoWithTerminator);

        // 3. 截取 32 字节（256位）作为 AES 密钥
        byte[] aesKeyBytes = Arrays.copyOf(okm, keyLength / 8);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }
    // 删除原有的 deriveAESKey 方法（PBKDF2 实现）

    // 修改 encrypt 方法，使用 hkdfDerive 派生密钥
    public static String encrypt(String plaintext, String sharedSecretBase64) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        // 打印后端生成的IV（用于对比前端提取的IV）
        System.out.println("后端加密IV（Hex）：" + bytesToHex(iv));

        byte[] sharedSecret = Base64.getDecoder().decode(sharedSecretBase64);
        // 使用HKDF派生AES密钥（关键：与前端解密的HKDF参数必须一致）
        SecretKey aesKey = hkdfDerive(sharedSecret, "ecdhe-aes-gcm".getBytes(StandardCharsets.UTF_8), 256);
        // 打印后端加密用的AES密钥（Hex，用于对比前端）
        System.out.println("后端加密AES密钥（Hex）：" + bytesToHex(aesKey.getEncoded()));

        // 后续加密逻辑不变...
        Cipher cipher = Cipher.getInstance(AES_MODE);
        GCMParameterSpec gcmParamSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmParamSpec);
        byte[] ciphertextWithTag = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] encryptedData = new byte[iv.length + ciphertextWithTag.length];
        System.arraycopy(iv, 0, encryptedData, 0, iv.length);
        System.arraycopy(ciphertextWithTag, 0, encryptedData, iv.length, ciphertextWithTag.length);

        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public static String decrypt(String encryptedDataBase64, String sharedSecretBase64) throws Exception {
        byte[] encryptedData = Base64.getDecoder().decode(encryptedDataBase64);
        System.out.println("encryptedDataBase64：" + encryptedDataBase64);
        // 打印后端接收的完整加密数据（Hex）
        System.out.println("后端加密数据（Hex）：" + bytesToHex(encryptedData));

        byte[] iv = Arrays.copyOfRange(encryptedData, 0, GCM_IV_LENGTH);
        // 打印后端IV（Hex）
        System.out.println("后端IV（Hex）：" + bytesToHex(iv));

        byte[] ciphertextWithTag = Arrays.copyOfRange(encryptedData, GCM_IV_LENGTH, encryptedData.length);
        // 打印后端密文+Tag（Hex）
        System.out.println("后端密文+Tag（Hex）：" + bytesToHex(ciphertextWithTag));

        byte[] sharedSecret = Base64.getDecoder().decode(sharedSecretBase64);

        // 新增：HKDF派生AES密钥（与前端参数严格一致）
        byte[] hkdfSalt = new byte[32]; // 32字节全0盐值（与前端hkdfSalt一致）
        byte[] hkdfInfo = "ecdhe-aes-gcm".getBytes(StandardCharsets.UTF_8); // 与前端info一致

        // HKDF-Extract
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(hkdfSalt, "HmacSHA256"));
        byte[] prk = mac.doFinal(sharedSecret);

        // HKDF-Expand（info + 0x01终止符）
        byte[] infoWithTerm = Arrays.copyOf(hkdfInfo, hkdfInfo.length + 1);
        infoWithTerm[hkdfInfo.length] = 0x01;
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        byte[] okm = mac.doFinal(infoWithTerm);

        // 截取32字节（256位）作为AES密钥
        SecretKeySpec aesKey = new SecretKeySpec(Arrays.copyOf(okm, 32), "AES");
        System.out.println("后端HKDF派生的AES密钥（Hex）：" + bytesToHex(aesKey.getEncoded()));

        Cipher cipher = Cipher.getInstance(AES_MODE);
        GCMParameterSpec gcmParamSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmParamSpec);

        byte[] plaintextBytes = cipher.doFinal(ciphertextWithTag);
        // 打印后端解密后的明文字节（Hex）
        System.out.println("后端明文字节（Hex）：" + bytesToHex(plaintextBytes));
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }

    // 辅助方法：字节数组转Hex
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * 修复：客户端和服务端使用完全相同的盐值和上下文信息
     */
    private static SecretKey deriveAESKey(byte[] sharedSecret, byte[] context) throws Exception {
        // 1. 盐值固定（双方一致）
        byte[] salt = KDF_SALT;

        // 2. 上下文信息双方一致（标识密钥用途）
        byte[] info = Arrays.copyOf(context, context.length);

        // 3. PBKDF2参数双方严格一致
        PBEKeySpec spec = new PBEKeySpec(
                new String(sharedSecret).toCharArray(), // 共享密钥（双方计算结果相同）
                salt,                                   // 盐值（双方相同）
                KDF_ITERATIONS,                         // 迭代次数（双方相同）
                AES_KEY_LENGTH                          // 密钥长度（双方相同）
        );
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] aesKeyBytes = factory.generateSecret(spec).getEncoded();

        return new SecretKeySpec(aesKeyBytes, "AES");
    }

}