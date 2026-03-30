package com.security.demo.backend.test;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class ECDHEWithEncryptionExample {
    private static final String CURVE_NAME = "secp256r1";
    private static final String AES_MODE = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int AES_KEY_LENGTH = 256;
    private static final int KDF_ITERATIONS = 65536;
    // 关键：双方使用相同的固定盐值（实际场景可协商后同步，如随公钥传输）
    private static final byte[] KDF_SALT = "finance-ecdhe-salt-2025".getBytes();

    static class Server {
        private KeyPair ephemeralKeyPair;
        private SecretKey aesKey;

        public void generateEphemeralKeyPair() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(CURVE_NAME);
            keyGen.initialize(ecSpec, new SecureRandom());
            this.ephemeralKeyPair = keyGen.generateKeyPair();
            System.out.println("服务端生成新的临时密钥对");
        }

        public String exportEphemeralPublicKey() {
            return Base64.getEncoder().encodeToString(ephemeralKeyPair.getPublic().getEncoded());
        }

        public void computeSharedSecretAndDeriveAES(String clientEphemeralPubBase64) throws Exception {
            byte[] clientPubBytes = Base64.getDecoder().decode(clientEphemeralPubBase64);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPubBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PublicKey clientPublicKey = keyFactory.generatePublic(keySpec);

            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(ephemeralKeyPair.getPrivate());
            keyAgreement.doPhase(clientPublicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();

            // 派生密钥时使用相同的上下文标识（如"ecdhe-aes-gcm"）
            this.aesKey = deriveAESKey(sharedSecret, "ecdhe-aes-gcm".getBytes());
            System.out.println("服务端AES密钥: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));
        }

        public String decrypt(String encryptedDataBase64) throws Exception {
            byte[] encryptedData = Base64.getDecoder().decode(encryptedDataBase64);
            byte[] iv = Arrays.copyOfRange(encryptedData, 0, GCM_IV_LENGTH);
            byte[] ciphertextWithTag = Arrays.copyOfRange(encryptedData, GCM_IV_LENGTH, encryptedData.length);

            Cipher cipher = Cipher.getInstance(AES_MODE);
            GCMParameterSpec gcmParamSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmParamSpec);

            return new String(cipher.doFinal(ciphertextWithTag), "UTF-8");
        }
    }

    static class Client {
        private KeyPair ephemeralKeyPair;
        private SecretKey aesKey;

        public void generateEphemeralKeyPair() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(CURVE_NAME);
            keyGen.initialize(ecSpec, new SecureRandom());
            this.ephemeralKeyPair = keyGen.generateKeyPair();
            System.out.println("客户端生成新的临时密钥对");
        }

        public String exportEphemeralPublicKey() {
            return Base64.getEncoder().encodeToString(ephemeralKeyPair.getPublic().getEncoded());
        }

        public void computeSharedSecretAndDeriveAES(String serverEphemeralPubBase64) throws Exception {
            byte[] serverPubBytes = Base64.getDecoder().decode(serverEphemeralPubBase64);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverPubBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PublicKey serverPublicKey = keyFactory.generatePublic(keySpec);

            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(ephemeralKeyPair.getPrivate());
            keyAgreement.doPhase(serverPublicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();

            // 客户端使用与服务端完全相同的上下文标识
            this.aesKey = deriveAESKey(sharedSecret, "ecdhe-aes-gcm".getBytes());
            System.out.println("客户端AES密钥: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));
        }

        public String encrypt(String plaintext) throws Exception {
            byte[] iv = new byte[GCM_IV_LENGTH];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(AES_MODE);
            GCMParameterSpec gcmParamSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmParamSpec);

            byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));

            byte[] encryptedData = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, encryptedData, 0, iv.length);
            System.arraycopy(ciphertext, 0, encryptedData, iv.length, ciphertext.length);

            return Base64.getEncoder().encodeToString(encryptedData);
        }
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

    public static void main(String[] args) {
        try {
            Server server1 = new Server();
            Client client1 = new Client();
            server1.generateEphemeralKeyPair();
            client1.generateEphemeralKeyPair();
            String serverPub1 = server1.exportEphemeralPublicKey();
            String clientPub1 = client1.exportEphemeralPublicKey();
            server1.computeSharedSecretAndDeriveAES(clientPub1);
            client1.computeSharedSecretAndDeriveAES(serverPub1);
            String msg1 = "会话1：Hello ECDHE（标准库实现）!";
            String enc1 = client1.encrypt(msg1);
            System.out.println("会话加密后：" + enc1);
            System.out.println("会话解密后：" + server1.decrypt(enc1));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}