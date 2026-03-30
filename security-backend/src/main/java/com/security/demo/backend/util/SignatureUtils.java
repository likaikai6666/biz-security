package com.security.demo.backend.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class SignatureUtils {
    private static final ObjectMapper objectMapper = new ObjectMapper();
    // 使用 JDK 内置的 SHA256withRSA 算法（兼容性强）
    private static final String DEFAULT_SIGN_ALG = "SHA256withRSA";

    /**
     * 深度排序 JSON 节点（与前端逻辑一致）
     */
    public static JsonNode deepSortJson(JsonNode node) {
        if (node == null || !node.isContainerNode()) {
            return node;
        }

        if (node.isArray()) {
            ArrayNode arrayNode = (ArrayNode) node;
            ArrayNode sortedArray = objectMapper.createArrayNode();
            for (JsonNode child : arrayNode) {
                sortedArray.add(deepSortJson(child));
            }
            return sortedArray;
        } else {
            ObjectNode originalObject = (ObjectNode) node;
            ObjectNode sortedObject = objectMapper.createObjectNode();

            List<String> keys = new ArrayList<>();
            Iterator<String> fieldNames = originalObject.fieldNames();
            while (fieldNames.hasNext()) {
                keys.add(fieldNames.next());
            }
            Collections.sort(keys);

            for (String key : keys) {
                JsonNode child = originalObject.get(key);
                sortedObject.set(key, deepSortJson(child));
            }
            return sortedObject;
        }
    }

    /**
     * 计算 JSON 体的 SHA-256 摘要（Base64 编码）
     */
    public static String calculateBodyDigest(JsonNode body) throws NoSuchAlgorithmException, JsonProcessingException {
        if (body == null) {
            body = objectMapper.createObjectNode();
        }
        JsonNode sortedBody = deepSortJson(body);
        String bodyStr = objectMapper.writeValueAsString(sortedBody);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(bodyStr.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }

    /**
     * 拼接待签名字符串（与前端规则一致）
     */
    public static String buildSignData(String appId, String timestamp, String nonce, String signAlg,
                                       String deviceId, String bodyDigest) {
        // 移除 X-Sign-Alg 参数，使用默认算法 SHA256withRSA
        return String.join("&",
                "X-App-Id=" + appId,
                "X-Timestamp=" + timestamp,
                "X-Nonce=" + nonce,
                "X-Sign-Alg=" + signAlg, // 补充前端的算法参数
                "deviceId=" + deviceId,
                "bodyDigest=" + bodyDigest
        );
    }

    public static boolean verifyWithClientPublicKey(String data, String signature, String clientPublicKey) {
        try {
            System.out.println("待验证签名：" + data);
            System.out.println("签名：" + signature);
            // 1. 解析前端公钥（PEM 格式）
            String publicKeyStr = clientPublicKey
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);

            // 2. 初始化 ECDSA 验证器
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            // 3. 验证签名
            verifier.update(data.getBytes(StandardCharsets.UTF_8));
            return verifier.verify(Base64.getDecoder().decode(signature));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}