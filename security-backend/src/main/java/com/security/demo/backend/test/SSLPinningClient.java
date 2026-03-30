package com.security.demo.backend.test;
import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class SSLPinningClient {
    public static OkHttpClient getSSLPinningClient() {
        try {
            // 1. 从后端项目的 resources 目录加载服务端证书
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream certInputStream = SSLPinningClient.class.getClassLoader().getResourceAsStream("server_cert.cer");
            if (certInputStream == null) {
                throw new RuntimeException("未找到证书文件 server_cert.cer，请检查 resources 目录");
            }
            X509Certificate serverCert = (X509Certificate) cf.generateCertificate(certInputStream);

            // 2. 构建信任管理器，仅信任预置证书
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("server", serverCert);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);
            X509TrustManager trustManager = (X509TrustManager) tmf.getTrustManagers()[0];

            // 3. 配置 SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);

            // 4. 配置 OkHttp 客户端，启用 SSL Pinning
            return new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.getSocketFactory(), trustManager)
                    .certificatePinner(new CertificatePinner.Builder()
                            .add("your-server-domain.com", "sha256/" + getCertSha256(serverCert)) // 替换为你的服务端域名
                            .build())
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("SSL Pinning 配置失败", e);
        }
    }

    // 辅助方法：计算证书的 SHA-256 哈希（用于 certificatePinner）
    private static String getCertSha256(X509Certificate cert) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] certBytes = cert.getEncoded();
        md.update(certBytes);
        byte[] hashBytes = md.digest();
        // 转换为 Base64 编码（CertificatePinner 要求 SHA-256 哈希以 Base64 形式传入）
        return java.util.Base64.getEncoder().encodeToString(hashBytes);
    }
}