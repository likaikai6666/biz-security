package com.security.demo.backend.test;

import javax.crypto.Cipher;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class LongTermKeyGenerator {

    // 密钥保存路径（长期存储，实际项目中应使用安全目录）
    private static final String PRIVATE_KEY_PATH = "long_term_private.key";
    private static final String PUBLIC_KEY_PATH = "long_term_public.key";

    public static void main(String[] args) throws Exception {
        // 1. 生成RSA长期密钥对（2048位，可根据安全需求升级到4096位）
        KeyPair rsaKeyPair = generateRSAKeyPair(2048);
        System.out.println("RSA密钥对生成成功：");
        System.out.println("私钥：" + encodeKey(rsaKeyPair.getPrivate()));
        System.out.println("公钥：" + encodeKey(rsaKeyPair.getPublic()));

        // 3. 保存RSA密钥对到文件（长期存储）
        saveKeyToFile(rsaKeyPair.getPrivate(), PRIVATE_KEY_PATH);
        saveKeyToFile(rsaKeyPair.getPublic(), PUBLIC_KEY_PATH);
        System.out.println("\n密钥对已保存到文件：" + PRIVATE_KEY_PATH + " 和 " + PUBLIC_KEY_PATH);

        // 4. 从文件加载密钥对（模拟后续使用）
        PrivateKey loadedPrivateKey = loadPrivateKey(PRIVATE_KEY_PATH);
        PublicKey loadedPublicKey = loadPublicKey(PUBLIC_KEY_PATH);
        System.out.println("\n从文件加载的公钥：" + encodeKey(loadedPublicKey));

        // 5. 验证密钥对有效性（用私钥签名，公钥验签）
        String data = "测试长期密钥对的有效性";
        String signature = sign(data, loadedPrivateKey);
        boolean verifyResult = verify(data, signature, loadedPublicKey);
        System.out.println("\n签名验证结果：" + (verifyResult ? "成功（密钥对有效）" : "失败（密钥对无效）"));
    }

    /**
     * 生成RSA密钥对
     * @param keySize 密钥长度（推荐2048/4096）
     */
    public static KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize, new SecureRandom()); // 随机数种子确保密钥唯一性
        return generator.generateKeyPair();
    }

    /**
     * 将密钥编码为Base64字符串（便于传输和存储）
     */
    public static String encodeKey(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * 保存密钥到文件（长期存储）
     */
    public static void saveKeyToFile(Key key, String path) throws Exception {
        Files.write(Paths.get(path), key.getEncoded());
    }

    /**
     * 从文件加载私钥
     */
    public static PrivateKey loadPrivateKey(String path) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(path));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes); // 私钥使用PKCS8格式
        return KeyFactory.getInstance("RSA").generatePrivate(spec); // 若为ECC，替换为"EC"
    }

    /**
     * 从文件加载公钥
     */
    public static PublicKey loadPublicKey(String path) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(path));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes); // 公钥使用X509格式
        return KeyFactory.getInstance("RSA").generatePublic(spec); // 若为ECC，替换为"EC"
    }

    /**
     * 用私钥签名数据
     */
    public static String sign(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA"); // 若为ECC，使用"SHA256withECDSA"
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    /**
     * 用公钥验证签名
     */
    public static boolean verify(String data, String signatureStr, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA"); // 与签名算法一致
        signature.initVerify(publicKey);
        signature.update(data.getBytes());
        byte[] signatureBytes = Base64.getDecoder().decode(signatureStr);
        return signature.verify(signatureBytes);
    }
}
