package com.security.demo.backend.service;

import com.security.demo.backend.aws.CreateKmsAsymmetricKeyUtil;
import com.security.demo.backend.model.*;
import com.security.demo.backend.util.ECDHEUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import software.amazon.awssdk.services.kms.model.KeyUsageType;

import java.security.KeyPair;
import java.util.Base64;
import java.util.UUID;

@Service
public class KeyExchangeService {
    @Autowired
    private SecurityService securityService;

    @Transactional(propagation = Propagation.REQUIRES_NEW) // 独立事务，避免长事务锁表
    public LongTermKeyExchangeResponse exchangeLongTermKey(LongTermKeyExchangeRequest request) {
        // 3. 检查设备是否已上传过公钥（若已存在，更新；否则新增）
        String deviceId = request.getDeviceId();
        AwsKmsResult encryptDecryptKey = CreateKmsAsymmetricKeyUtil.
                createAsymmetricKey(KeyUsageType.ENCRYPT_DECRYPT,
                        CreateKmsAsymmetricKeyUtil.getLongTermEncryptKeyName(deviceId));
        AwsKmsResult signKey = CreateKmsAsymmetricKeyUtil.
                createAsymmetricKey(KeyUsageType.SIGN_VERIFY,
                        CreateKmsAsymmetricKeyUtil.getLongTermSignKeyName(deviceId));
        try {
            securityService.setLongTermPublicKey(deviceId, request.getClientPublicKey());
        } catch (Exception e){
            e.printStackTrace();
        }
        return new LongTermKeyExchangeResponse(
                encryptDecryptKey.getPublicKey(),
                signKey.getPublicKey()
        );
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public ShortTermKeyExchangeResponse exchangeShortTermKey(ShortTermKeyExchangeRequest request) throws Exception {
        // 3. 检查设备是否已上传过公钥（若已存在，更新；否则新增）
        String deviceId = request.getDeviceId();
        KeyPair keyPair = ECDHEUtil.generateEphemeralKeyPair();
        String privateKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        securityService.setShortTermKey(deviceId, privateKeyBase64,publicKeyBase64, request.getClientPublicKey());

        return new ShortTermKeyExchangeResponse(
                publicKeyBase64,
                "签名",
                UUID.randomUUID().toString()
        );
    }
}
