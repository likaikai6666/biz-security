package com.security.demo.backend.controller;

import com.security.demo.backend.model.*;
import com.security.demo.backend.service.KeyExchangeService;
import com.security.demo.backend.service.SecurityService;
import com.security.demo.backend.util.ECDHEUtil;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import io.swagger.v3.oas.annotations.Operation;

import java.util.UUID;

@RestController
@RequestMapping("/api/security")
public class SecurityController {

    private final PasswordEncoder passwordEncoder;

    public SecurityController(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Autowired
    private KeyExchangeService keyExchangeService;
    @Autowired
    private SecurityService securityService;
    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    /**
     * App 上传长期公钥，服务端返回自身长期公钥
     *
     * @param request App 端请求参数（包含设备信息、公钥、签名等）
     * @return 服务端公钥及相关信息
     */
    @PostMapping("/long-term-key/exchange")
    @Operation(summary = "交换长期公钥", description = "交换长期公钥")
    public ResponseEntity<ApiResponse<LongTermKeyExchangeResponse>> exchangeLongTermKey(
            @Valid @RequestBody LongTermKeyExchangeRequest request) {
        // 调用业务层处理公钥交换逻辑
        LongTermKeyExchangeResponse response = keyExchangeService.exchangeLongTermKey(request);
        // 封装标准成功响应
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PostMapping("/short-term-key/exchange")
    @Operation(summary = "交换短期公钥", description = "交换短期公钥")
    public ResponseEntity<ApiResponse<ShortTermKeyExchangeResponse>> exchangeShortTermKey(
            @Valid @RequestBody ShortTermKeyExchangeRequest request) throws Exception {
        // 调用业务层处理公钥交换逻辑
        ShortTermKeyExchangeResponse response = keyExchangeService.exchangeShortTermKey(request);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    // 公开接口：测试加密
    @PostMapping("/business/encrypt")
    @Operation(summary = "业务加解密接口", description = "业务接口，需要加密及解密")
    public ResponseVo<String> encryptBusinessData(@RequestBody BusinessRequest request) throws Exception {
        // 1. 获取请求参数（加密文本 + 设备ID）
        String encryptedText = request.getText();
        String deviceId = request.getDeviceId();
        // 2. 原有业务逻辑不变
        String sharedSecretBase64 = securityService.getShortTermSharedKey(deviceId);
        System.out.println(">>>>>>>>>>获取的请求解密数据使用的密钥：>>>>>>>>：" + sharedSecretBase64);
        String param = null;
        try {
            param = ECDHEUtil.decrypt(encryptedText, sharedSecretBase64);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println(">>>>>>>>>>获取的请求解密的数据：>>>>>>>>：" + param);

        String result = "....这个是服务端返回的结果:"+ UUID.randomUUID();
        String encryptedResult = ECDHEUtil.encrypt(result, sharedSecretBase64);

        System.out.println("base64Encrypted:"+encryptedResult);
        // 4. 返回统一响应格式（含状态码、消息、数据）
        return new ResponseVo<>(0, "加密响应成功", encryptedResult);
    }
}