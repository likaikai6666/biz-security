package com.security.demo.backend.enums;

/**
 * 密钥前缀枚举类，用于区分长期密钥和短期密钥
 * 适用于密钥存储（如Redis、KMS）、日志打印等场景，明确密钥生命周期
 */
public enum KeyPrefixEnum {

    /**
     * 长期密钥前缀：用于标识长期有效的密钥（如加密/签名的长期非对称密钥）
     * 特点：生命周期长（如1年以上），轮换频率低，与主体身份长期绑定
     */
    LONG_TERM("long-term-"),

    /**
     * 短期密钥前缀：用于标识短期有效的临时密钥（如ECDHE协商的会话密钥、临时对称密钥）
     * 特点：生命周期短（如会话级、小时级），一次性或高频轮换，仅用于单次/短期交互
     */
    SHORT_TERM("short-term-"),
    SHORT_TERM_PRIVATE("short-term-private-"),
    SHORT_TERM_SERVER_PUBLIC("short-term-server-public-"),
    SHORT_TERM_CLIENT_PUBLIC("short-term-client-public-"),
    SHORT_TERM_SHARED("short-term-shared-");

    /**
     * 密钥前缀字符串
     */
    private final String prefix;

    /**
     * 构造函数：初始化密钥前缀
     *
     * @param prefix 前缀字符串
     */
    KeyPrefixEnum(String prefix) {
        this.prefix = prefix;
    }

    /**
     * 获取前缀字符串
     *
     * @return 密钥前缀（如 "long-term-"）
     */
    public String getPrefix() {
        return prefix;
    }

    /**
     * 生成带前缀的完整密钥标识
     *
     * @param keyId 密钥唯一ID（如密钥名称、UUID等）
     * @return 带前缀的密钥标识（如 "long-term-rsa-encrypt-key-123"）
     */
    public String generateKeyId(String keyId) {
        if (keyId == null || keyId.trim().isEmpty()) {
            throw new IllegalArgumentException("密钥ID不能为空");
        }
        return prefix + keyId;
    }
}
