import axios from 'axios';
import securityUtils from './securityUtils';

// 全局存储密钥（生产环境建议用更安全的存储方式）
let globalKeys = {
    longTermPrivateKey: null, // 长期私钥
    sharedSecret: null, // 共享密钥（ECDHE协商后）
    serverLongTermSignPublicKey: null // 服务端长期公钥（用于验证响应签名）
};

// 提供设置密钥的方法（供业务组件调用）
export const setGlobalKeys = (keys) => {
    globalKeys = {...globalKeys, ...keys};
};

export const getGlobalKeys = () => {
    return {...globalKeys}; // 返回拷贝，防止外部篡改原对象
};

// 创建axios实例
const api = axios.create({
    baseURL: '', // 根据实际后端地址配置
    headers: {
        'Content-Type': 'application/json'
    }
});

// 请求拦截器：统一处理鉴权、签名
api.interceptors.request.use(async (config) => {
    // 1. 添加 Token 鉴权
    const token = localStorage.getItem('accessToken');
    const tokenType = localStorage.getItem('tokenType') || 'Bearer';
    if (token) {
        config.headers.Authorization = `${tokenType} ${token}`;
    }

    // 2. 过滤无需处理的接口（跳过 Token 获取、密钥交换接口，仅处理业务接口）
    const ignoreUrls = [
        '/oauth2/token', // 跳过 Token 获取
        '/long-term-key/exchange', // 跳过长期公钥交换
        '/short-term-key/exchange' // 跳过临时公钥交换
    ];
    if (config.method?.toUpperCase() !== 'POST' || ignoreUrls.some(url => config.url.includes(url))) {
        return config;
    }

    // 3. 签名必要参数（保持原有逻辑）
    const appId = 'finance-app-001';
    const signAlg = 'RSA-PSS-SHA256';
    const timestamp = Date.now();
    const nonce = securityUtils.generateNonce();
    const deviceId = config.data?.deviceId || '';

    // 4. 保存原始 Body（用于签名摘要，加密后替换原 Body）
    const originalBody = config.data || {};
    const sortedOriginalBody = securityUtils.deepSortObject(originalBody);
    const originalBodyStr = JSON.stringify(sortedOriginalBody);
    const bodyDigest = await securityUtils.calculateSHA256Digest(originalBodyStr); // 签名用原始数据摘要

    // 5. 拼接待签名字符串（保持原有逻辑，签名的是原始数据摘要）
    const signData = [
        `X-App-Id=${appId}`,
        `X-Timestamp=${timestamp}`,
        `X-Nonce=${nonce}`,
        `X-Sign-Alg=${signAlg}`,
        `deviceId=${deviceId}`,
        `bodyDigest=${bodyDigest}`
    ].join('&');
    console.log("请求签名字符串:", signData);

    // 6. 签名逻辑（保持原有，用长期私钥签名原始数据摘要）
    let signature = '';
    if (globalKeys.longTermPrivateKey) {
        signature = await securityUtils.signWithPrivateKey(
            globalKeys.longTermPrivateKey,
            signData
        );
        console.log("请求签名结果:", signature);
    }

    // 7. 核心：Body 加密（仅业务接口，使用 ECDHE 协商的 AES 密钥）
    let encryptedBody = {};
    if (globalKeys.sharedSecret) {
        console.log("开始加密请求 Body（AES-GCM）...");
        // 7.1 加密原始 Body（AES-GCM 算法，返回加密后的数据 + IV + 认证标签）
        const encryptResult = await securityUtils.encryptData(
            originalBodyStr, // 原始 Body 字符串
            globalKeys.sharedSecret // 协商出的 AES 密钥（Base64 格式）
        );
        // 7.2 构造加密后的 Body（传给后端用于解密）
        encryptedBody = {
            encryptedData: encryptResult.encryptedData, // 加密后的 Body（Base64）
            iv: encryptResult.iv, // 随机 IV（Base64，AES-GCM 必需）
            authTag: encryptResult.authTag // 认证标签（Base64，AES-GCM 必需）
        };
        console.log("Body 加密完成，加密后数据（前30位）:", encryptResult.encryptedData.substring(0, 30));
    } else {
        // 若未协商密钥（异常情况），仍传原始 Body（可根据需求抛出错误）
        encryptedBody = originalBody;
        console.warn("未获取到共享密钥，Body 未加密");
    }

    // 8. 构造最终请求头（包含签名信息 + 加密元信息）
    config.headers = {
        ...config.headers,
        'Authorization': `${tokenType} ${token}`,
        'X-App-Id': appId,
        'X-Device-Id': deviceId,
        'X-Timestamp': timestamp,
        'X-Nonce': nonce,
        'X-Sign-Alg': signAlg,
        'X-Signature': signature,
        'Content-Type': 'application/json;charset=UTF-8',
        // 新增：标记是否加密（后端可根据此判断是否解密）
        'X-Encrypt-Type': globalKeys.sharedSecret ? 'AES-GCM-256' : 'NONE'
    };

    // 9. 替换请求 Body 为加密后的数据
    config.data = encryptedBody;

    // 保存请求头和原始 Body 摘要（供响应拦截器使用）
    config.__requestHeaders = { ...config.headers };
    config.__originalBodyDigest = bodyDigest;

    return config;
});

// 响应拦截器：验证响应签名 + 处理解密
api.interceptors.response.use(async (response) => {
    const {config, data, headers} = response;
    const keys = getGlobalKeys();
    // 1. 验证响应签名（跳过登录接口和无公钥的情况）
    if (
        !config.url.includes('/oauth2/token') &&
        keys.serverLongTermSignPublicKey &&
        config.method?.toUpperCase() === 'POST'
    ) {
        // 1.1 从响应头获取签名参数（注意：axios会将header字段转为小写，需用小写访问）
        const signature = headers['x-signature']; // 对应后端的X-Signature
        const dataDigest = headers['x-data-digest']; // 对应后端的X-Data-Digest
        const timestamp = headers['x-timestamp']; // 对应后端的X-Timestamp
        const nonce = headers['x-nonce']; // 对应后端的X-Nonce
        const signAlg = headers['x-sign-alg']; // 对应后端的X-Sign-Alg
        const appId = headers['x-app-id'];
        const requestHeaders = config.__requestHeaders || {};
        const deviceId = requestHeaders['X-Device-Id'] || '';
        console.log("headers:"+JSON.stringify(headers));// 从请求头取原始大写格式
        console.log("signature:"+signature);
        console.log("dataDigest:"+dataDigest);
        console.log("timestamp:"+timestamp);
        console.log("nonce:"+nonce);
        console.log("signAlg:"+signAlg);
        // 1.2 校验签名参数完整性
        if (!signature || !dataDigest || !timestamp || !nonce || !signAlg) {
            console.error('响应签名参数不完整（X-Signature、X-Data-Digest等）');
            throw new Error('响应签名验证失败：参数缺失');
        }

        // 1.3 校验算法一致性
        if (signAlg !== 'RSA-PSS-SHA256') {
            console.error(`响应签名算法不匹配：预期${'RSA-PSS-SHA256'}，实际${signAlg}`);
            throw new Error('响应签名验证失败：算法不匹配');
        }

        // 1.4 验证时间戳（防重放，允许5分钟内）
        const now = Date.now();
        const fiveMinutes = 5 * 60 * 1000;
        if (Math.abs(now - Number(timestamp)) > fiveMinutes) {
            console.error(`响应时间戳过期：${timestamp}（当前：${now}）`);
            throw new Error('响应签名验证失败：时间戳过期');
        }

        // 1.5 生成客户端数据摘要并校验
        const sortedData = securityUtils.deepSortObject(data);
        const dataStr = JSON.stringify(sortedData);
        const clientDigest = await securityUtils.calculateSHA256Digest(dataStr);
        if (clientDigest !== dataDigest) {
            console.error(`响应数据摘要不匹配：服务端${dataDigest}，客户端${clientDigest}`);
            throw new Error('响应签名验证失败：数据被篡改');
        }

        // 1.6 拼接待验证的签名字符串（严格匹配后端格式，使用X-前缀大写）
        const verifyData = [
            `X-App-Id=${appId}`,
            `X-Timestamp=${timestamp}`,   // 与后端一致，带X-前缀大写
            `X-Nonce=${nonce}`,           // 与后端一致，带X-前缀大写
            `X-Sign-Alg=${signAlg}`,      // 与后端一致，带X-前缀大写
            `deviceId=${deviceId}`,       // deviceId无X-前缀，保持不变
            `bodyDigest=${dataDigest}`    // bodyDigest无X-前缀，保持不变
        ].join('&');
        console.log("响应验签字符串:", verifyData);

        // 1.7 用服务端公钥验证签名
        const verifyResult = await securityUtils.verifyWithPublicKey(
            keys.serverLongTermSignPublicKey,
            verifyData,
            signature
        );
        if (!verifyResult) {
            console.error('响应签名验证失败：签名不匹配');
            throw new Error('响应签名验证失败：签名无效');
        }
        console.log('响应签名验证成功');
    }

    // 2. 解密响应数据（如果存在共享密钥且是加密接口）
    // try {
    //     data.data = await securityUtils.decryptData(data.data, keys.sharedSecret);
    //     console.log('响应数据解密成功');
    // } catch (e) {
    //     console.error('响应数据解密失败:', e);
    //     throw new Error('响应解密失败：' + e.message);
    // }


    return response;
}, (error) => {
    console.error('请求错误：', error.response?.data || error.message);
    return Promise.reject(error);
});

export default api;