package com.security.demo.backend.test;

import okhttp3.*;
import org.json.JSONObject;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyExchangeClient {
    public void sendPublicKeyToServer() {
        try {
            // 1. 生成 App 长期密钥对
            KeyPair appKeyPair = AppKeyManager.generateLongTermKeyPair();
            PublicKey appPublicKey = appKeyPair.getPublic();
            PrivateKey appPrivateKey = appKeyPair.getPrivate();

            // 2. 签名公钥
            String deviceId = "device_123456"; // 设备唯一标识
            String signedData = AppKeyManager.signPublicKey(appPublicKey, appPrivateKey, deviceId);

            // 3. 通过 SSL Pinning 通道发送
            OkHttpClient client = SSLPinningClient.getSSLPinningClient();
            MediaType JSON = MediaType.parse("application/json; charset=utf-8");
            JSONObject json = new JSONObject();
            json.put("signedData", signedData);
            json.put("deviceId", deviceId);

            Request request = new Request.Builder()
                    .url("https://your-server-domain.com/api/registerPublicKey")
                    .post(RequestBody.create(JSON, json.toString()))
                    .build();

            Response response = client.newCall(request).execute();
            if (response.isSuccessful()) {
                System.out.println("公钥发送成功，服务端验证通过");
            } else {
                System.out.println("公钥发送失败：" + response.message());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
