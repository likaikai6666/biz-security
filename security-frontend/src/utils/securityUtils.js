// 公共安全工具：签名、加密、密钥处理等
export default {
    // 生成32位随机nonce（防重放）
    generateNonce() {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let nonce = '';
        for (let i = 0; i < 32; i++) {
            nonce += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return nonce;
    },

    // 递归排序对象所有层级的key（确保签名数据一致）
    deepSortObject(obj) {
        if (typeof obj !== 'object' || obj === null) return obj;
        if (Array.isArray(obj)) return obj.map(item => this.deepSortObject(item));
        const sortedObj = {};
        Object.keys(obj).sort().forEach(key => {
            sortedObj[key] = this.deepSortObject(obj[key]);
        });
        return sortedObj;
    },

    // 计算SHA-256摘要（Base64）
    async calculateSHA256Digest(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        return btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));
    },
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        let binary = '';
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    },
    convertToDerSignature(rawSignature) {
        const r = rawSignature.slice(0, 32);
        const s = rawSignature.slice(32, 64);

        // 移除 r 和 s 前面的无效零字节（DER 编码要求）
        function trimLeadingZeros(bytes) {
            let start = 0;
            while (start < bytes.length && bytes[start] === 0) {
                start++;
            }
            return start === 0 ? bytes : bytes.slice(start);
        }

        const rTrimmed = trimLeadingZeros(r);
        const sTrimmed = trimLeadingZeros(s);

        // 构建 DER 编码结构：30 [总长度] 02 [r长度] [r] 02 [s长度] [s]
        const rLen = rTrimmed.length;
        const sLen = sTrimmed.length;
        const totalLen = 2 + rLen + 2 + sLen;

        const der = new Uint8Array(2 + totalLen);
        der[0] = 0x30; // DER 序列标签
        der[1] = totalLen;
        der[2] = 0x02; // 整数标签（r）
        der[3] = rLen;
        der.set(rTrimmed, 4);
        der[4 + rLen] = 0x02; // 整数标签（s）
        der[5 + rLen] = sLen;
        der.set(sTrimmed, 6 + rLen);

        return der;
    },

    // RSA-PSS签名（私钥签名）
    async signWithPrivateKey(privateKey, data) {
        console.log("signWithPrivateKey.data:" + data);
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        // 生成原始签名（r + s 格式）
        const rawSignature = await crypto.subtle.sign(
            {name: "ECDSA", hash: {name: "SHA-256"}},
            privateKey,
            dataBuffer
        );
        // 转换为 DER 编码
        const derSignature = this.convertToDerSignature(new Uint8Array(rawSignature));
        // 编码为 Base64
        return this.arrayBufferToBase64(derSignature.buffer);
    },
    // ArrayBuffer转PEM格式
    arrayBufferToPem(buffer, type) {
        const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
        return `-----BEGIN ${type}-----\n` +
            base64.match(/.{1,64}/g).join('\n') +
            `\n-----END ${type}-----`;
    },

    // Base64转PEM格式
    base64ToPem(base64Str, type) {
        if (!base64Str) throw new Error('Base64公钥为空');
        const cleanBase64 = base64Str.replace(/\s+/g, '');
        const pemLines = [];
        for (let i = 0; i < cleanBase64.length; i += 64) {
            pemLines.push(cleanBase64.slice(i, i + 64));
        }
        return `-----BEGIN ${type}-----\n${pemLines.join('\n')}\n-----END ${type}-----`;
    },

    // 验证Base64格式
    isValidBase64(str) {
        return typeof str === 'string' && str.length % 4 === 0 && /^[A-Za-z0-9+/]+(?:=){0,2}$/.test(str);
    },

    // PEM转CryptoKey
    async pemToCryptoKey(base64Str, type, algorithm) {
        if (!this.isValidBase64(base64Str)) {
            throw new Error(`无效的Base64格式：${base64Str.substring(0, 30)}...`);
        }

        const binaryStr = atob(base64Str);
        const buffer = new ArrayBuffer(binaryStr.length);
        const view = new Uint8Array(buffer);
        for (let i = 0; i < binaryStr.length; i++) {
            view[i] = binaryStr.charCodeAt(i);
        }

        return crypto.subtle.importKey(
            'spki',
            buffer,
            {name: algorithm, namedCurve: 'P-256'},
            false,
            []
        );
    },

    // HKDF派生密钥
    async hkdfDerive(sharedSecret, infoStr) {
        const info = new TextEncoder().encode(infoStr);
        const salt = new Uint8Array(32);

        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            sharedSecret,
            {name: 'HKDF'},
            false,
            ['deriveKey']
        );

        return crypto.subtle.deriveKey(
            {name: 'HKDF', salt, info, hash: 'SHA-256'},
            keyMaterial,
            {name: 'AES-GCM', length: 256},
            true,
            ['encrypt', 'decrypt']
        );
    },

    // AES-GCM加密
    async encryptData(plaintext, sharedSecretBase64) {
        const sharedSecret = Uint8Array.from(atob(sharedSecretBase64), c => c.charCodeAt(0));
        const hkdfInfo = new TextEncoder().encode("ecdhe-aes-gcm");
        const hkdfSalt = new Uint8Array(32);

        // 派生AES密钥
        const derivedKey = await crypto.subtle.importKey(
            'raw',
            sharedSecret,
            {name: 'HKDF'},
            false,
            ['deriveKey']
        );
        const aesKey = await crypto.subtle.deriveKey(
            {name: 'HKDF', salt: hkdfSalt, info: hkdfInfo, hash: 'SHA-256'},
            derivedKey,
            {name: 'AES-GCM', length: 256},
            false,
            ['encrypt']
        );

        // 生成随机IV并加密
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const plaintextBytes = new TextEncoder().encode(plaintext);
        const ciphertext = await crypto.subtle.encrypt(
            {name: 'AES-GCM', iv},
            aesKey,
            plaintextBytes
        );

        // 拼接IV和密文（IV占前12字节）
        const combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(ciphertext), iv.length);
        return btoa(String.fromCharCode(...combined));
    },

    // AES-GCM解密（修复Base64解码问题）
    async decryptData(encryptedBase64, sharedSecretBase64) {
        const encryptedBytes = this.base64ToUint8Array(encryptedBase64);
        // 验证数据长度：IV(12字节) + 密文(至少1字节) + Tag(16字节) = 至少29字节
        if (encryptedBytes.length < 29) {
            throw new Error(`解密失败：加密数据过短（实际长度：${encryptedBytes.length}字节，至少需要29字节）`);
        }

        const iv = encryptedBytes.slice(0, 12);
        const ciphertextWithTag = encryptedBytes.slice(12);

        // 验证Tag长度（AES-GCM的Tag固定16字节）
        if (ciphertextWithTag.length < 16) {
            throw new Error(`解密失败：认证标签过短（实际长度：${ciphertextWithTag.length}字节，需要16字节）`);
        }

        // 修复2：共享密钥的Base64解码同样替换
        const sharedSecret = this.base64ToUint8Array(sharedSecretBase64);
        const hkdfSalt = new Uint8Array(32);
        const hkdfInfo = new TextEncoder().encode("ecdhe-aes-gcm");

        // 派生AES密钥（逻辑不变）
        const hkdfKeyMaterial = await crypto.subtle.importKey(
            'raw',
            sharedSecret,
            {name: 'HKDF'},
            false,
            ['deriveKey']
        );
        const aesKey = await crypto.subtle.deriveKey(
            {name: 'HKDF', salt: hkdfSalt, info: hkdfInfo, hash: 'SHA-256'},
            hkdfKeyMaterial,
            {name: 'AES-GCM', length: 256},
            false,
            ['decrypt']
        );

        // 解密（逻辑不变）
        const plaintextBytes = await crypto.subtle.decrypt(
            {name: 'AES-GCM', iv},
            aesKey,
            ciphertextWithTag
        );
        return new TextDecoder().decode(plaintextBytes);
    },

    base64ToUint8Array(base64String) {
        console.log("base64String:"+base64String);
        try {
            // 步骤1：移除所有非Base64字符（空格、换行、制表符等）
            base64String = base64String.replace(/[^A-Za-z0-9+/=]/g, '');

            // 步骤2：处理URL安全的Base64（若后端使用）
            base64String = base64String.replace(/-/g, '+').replace(/_/g, '/');

            // 步骤3：补充Base64填充符（确保长度为4的倍数）
            const padLength = (4 - (base64String.length % 4)) % 4;
            base64String += '='.repeat(padLength);

            // 步骤4：解码并转换为Uint8Array
            const binaryString = atob(base64String);
            const uint8Array = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                uint8Array[i] = binaryString.charCodeAt(i);
            }
            return uint8Array;
        } catch (e) {
            console.error('Base64解码失败，处理后字符串:', base64String, '错误:', e);
            throw new Error('解密失败：无效的Base64格式');
        }
    },
    /**
     * 使用服务端公钥验证签名
     * @param {string} publicKeyPem - 服务端公钥（PEM格式，如 "-----BEGIN PUBLIC KEY-----..."）
     * @param {string} data - 待验证的原始数据（与后端签名时的 data 一致）
     * @param {string} signatureBase64 - 后端返回的签名（Base64格式）
     * @returns {Promise<boolean>} - 验证结果（true=通过，false=失败）
     */
    /**
     * 改用 ECDSA-SHA256 验证签名
     */
    async verifyWithPublicKey(publicKeyPem, data, signatureBase64) {
        try {
            // 1. 解析公钥（同之前）
            const publicKeyClean = publicKeyPem
                .replace(/-----BEGIN PUBLIC KEY-----/, '')
                .replace(/-----END PUBLIC KEY-----/, '')
                .replace(/\s+/g, '');
            const publicKeyBuffer = this.base64ToUint8Array(publicKeyClean);

            // 2. 导入 ECDSA 公钥（明确 P-256 曲线）
            const publicKey = await window.crypto.subtle.importKey(
                'spki',
                publicKeyBuffer,
                {
                    name: 'ECDSA',
                    namedCurve: 'P-256', // 严格匹配 KMS 曲线
                    hash: 'SHA-256'
                },
                false,
                ['verify']
            );

            // 3. 解码签名并解析 DER 格式
            const signatureDerBuffer = this.base64ToUint8Array(signatureBase64);
            const signatureRawBuffer = this.parseEcdsaDerSignature(signatureDerBuffer); // 关键步骤

            // 4. 编码待验证数据
            const encoder = new TextEncoder();
            const dataBuffer = encoder.encode(data);

            // 5. 验证签名
            return await window.crypto.subtle.verify(
                {
                    name: 'ECDSA',
                    hash: 'SHA-256'
                },
                publicKey,
                signatureRawBuffer, // 使用解析后的原始签名
                dataBuffer
            );

        } catch (error) {
            console.error('ECDSA 验证失败:', error);
            return false;
        }
    },
    /**
     * 解析 ECDSA 签名的 ASN.1 DER 编码，提取 r 和 s 并重组为 64 字节原始签名
     */
    parseEcdsaDerSignature(derSignature) {
        let offset = 0;
        // 检查 DER 头部（序列标识）
        if (derSignature[offset++] !== 0x30) {
            throw new Error('无效的 ECDSA DER 签名（缺少序列标识）');
        }
        // 检查长度
        const length = derSignature[offset++];
        if (length + 2 !== derSignature.byteLength) {
            throw new Error('无效的 ECDSA DER 签名长度');
        }

        // 解析 r（整数类型）
        if (derSignature[offset++] !== 0x02) {
            throw new Error('无效的 r 标识');
        }
        const rLength = derSignature[offset++];
        let r = derSignature.slice(offset, offset + rLength);
        offset += rLength;

        // 解析 s（整数类型）
        if (derSignature[offset++] !== 0x02) {
            throw new Error('无效的 s 标识');
        }
        const sLength = derSignature[offset++];
        let s = derSignature.slice(offset, offset + sLength);

        // 确保 r 和 s 都是 32 字节（P-256 曲线要求）
        r = this.padTo32Bytes(r);
        s = this.padTo32Bytes(s);

        // 拼接 r + s 为 64 字节原始签名
        return new Uint8Array([...r, ...s]);
    },

    /**
     * 补全字节数组为 32 字节（前端验证要求）
     */
    padTo32Bytes(bytes) {
        if (bytes.byteLength === 32) return bytes;
        // 若长度不足，前面补 0；若过长，截取后 32 字节
        const padded = new Uint8Array(32);
        if (bytes.byteLength > 32) {
            padded.set(bytes.slice(bytes.byteLength - 32));
        } else {
            padded.set(bytes, 32 - bytes.byteLength);
        }
        return padded;
    }
};