package com.security.demo.backend.util;

import org.springframework.stereotype.Component;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 简单的Nonce缓存，用于防重放攻击
 * 存储已使用的nonce，定期清理过期数据
 */
@Component
public class NonceCache {

    // 存储已使用的nonce（线程安全的Set）
    private final Set<String> nonceStorage = new HashSet<>();

    // 定时清理线程池（用于定期删除过期nonce）
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    // 初始化：启动定时清理任务（每5分钟清理一次，与接口超时时间保持一致）
    public NonceCache() {
        // 延迟5分钟后首次执行，之后每5分钟执行一次
        scheduler.scheduleAtFixedRate(this::cleanExpiredNonce, 5, 5, TimeUnit.MINUTES);
    }

    /**
     * 尝试添加nonce，若不存在则添加成功（表示未被使用过）
     * @param nonce 随机字符串
     * @param expireMinutes 过期时间（分钟），建议与接口超时时间一致（如5分钟）
     * @return true=添加成功（未使用过），false=已存在（重复请求）
     */
    public synchronized boolean tryAdd(String nonce, int expireMinutes) {
        // 若nonce已存在，返回false（重复请求）
        if (nonceStorage.contains(nonce)) {
            return false;
        }
        // 否则添加到缓存
        nonceStorage.add(nonce);
        return true;
    }

    /**
     * 清理过期的nonce（此处简化处理，直接清空缓存，实际应按时间戳过滤）
     * 注意：真实场景需存储nonce的创建时间，清理时删除超过expireMinutes的记录
     */
    private synchronized void cleanExpiredNonce() {
        // 简单实现：直接清空缓存（适合测试，生产环境需优化）
        nonceStorage.clear();
        // 生产环境建议替换为：
        // 1. 用Map<String, Long>存储nonce和创建时间戳
        // 2. 遍历Map，删除创建时间超过expireMinutes的记录
    }

    /**
     * 销毁时关闭线程池（防止资源泄漏）
     */
    public void destroy() {
        scheduler.shutdown();
    }
}
