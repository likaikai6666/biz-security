package com.security.demo.backend.util;

import org.springframework.stereotype.Component;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
public class SignatureValidator {

    /**
     * 验证签名
     * @param data 原始数据（待验证的内容）
     * @param signature 待验证的签名（Base64编码）
     * @param publicKeyPem 公钥（PEM格式）
     * @return 验证是否通过
     */
    public boolean validate(String data, String signature, String publicKeyPem) {
        try {
            // 解析PEM公钥（去除首尾标识）
            String publicKeyStr = publicKeyPem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);

            // 转换为PublicKey对象
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            // 验证签名
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(data.getBytes());
            return sig.verify(Base64.getDecoder().decode(signature));
        } catch (Exception e) {
            // 验证失败（异常视为验证不通过）
            return false;
        }
    }
}
