package com.security.demo.backend.model;

import lombok.Data;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;

import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.time.LocalDateTime;

/**
 * 设备与长期公钥的绑定关系实体
 * 存储 App 端上传的长期公钥及设备信息
 */
@Data
@DynamicInsert // 动态插入（只插入非空字段）
@DynamicUpdate // 动态更新（只更新修改过的字段）
public class DevicePublicKey {

    /**
     * 主键 ID（自增）
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // 自增策略（MySQL 适用）
    private Long id;


    private String deviceId;


    private String encryptPublicKey;

    private String signPublicKey;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;

    private LocalDateTime expireAt;

    private Integer status = 1; // 默认正常


    // 构造器
    public DevicePublicKey() {
    }

    /**
     * 新建设备公钥记录时使用的构造器
     *
     * @param deviceId         设备唯一标识
     * @param encryptPublicKey App 公钥
     * @param signPublicKey
     */
    public DevicePublicKey(String deviceId, String encryptPublicKey, String signPublicKey) {
        this.deviceId = deviceId;
        this.encryptPublicKey = encryptPublicKey;
        this.signPublicKey = signPublicKey;
        this.createTime = LocalDateTime.now();
        this.updateTime = LocalDateTime.now();
        // 过期时间默认设为 1 年后（与响应中的 keyExpireAt 保持一致）
        this.expireAt = LocalDateTime.now().plusYears(1);
    }


    /**
     * 更新设备公钥（如公钥轮换时）
     *
     * @param encryptPublicKey 新的 App 公钥
     * @param signPublicKey
     */
    public void buildPublicKey(String encryptPublicKey, String signPublicKey) {
        this.encryptPublicKey = encryptPublicKey;
        this.signPublicKey = signPublicKey;
        this.updateTime = LocalDateTime.now();
        // 公钥轮换后，过期时间延长 1 年
        this.expireAt = LocalDateTime.now().plusYears(1);
        this.status = 1; // 重置为正常状态
    }


    /**
     * 标记公钥失效（如设备解绑）
     */
    public void invalidate() {
        this.status = 0;
        this.updateTime = LocalDateTime.now();
    }
}
