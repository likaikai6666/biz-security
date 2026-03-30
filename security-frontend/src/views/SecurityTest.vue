<template>
  <div class="security-test-container">
    <h2>ECDHE密钥交换与加密通信测试</h2>

    <!-- 登录区域 -->
    <div class="section">
      <h3>0. 用户登录（获取Token）</h3>
      <div class="input-group">
        <label>用户名：</label>
        <input v-model="loginUsername" placeholder="输入用户名" />
      </div>
      <div class="input-group">
        <label>密码：</label>
        <input v-model="loginPassword" type="password" placeholder="输入密码" />
      </div>
      <button @click="login" :disabled="!loginUsername || !loginPassword">
        登录获取Token
      </button>
      <div v-if="accessToken" class="response-area">
        <p>当前Token：</p>
        <textarea class="key-display" :value="accessToken" readonly rows="3"></textarea>
        <p>Token类型：{{ tokenType }}</p>
        <p>过期时间：{{ expiresIn }}秒后</p>
        <button @click="logout">注销登录</button>
      </div>
    </div>

    <!-- 设备ID输入 -->
    <div class="input-group">
      <label>设备ID：</label>
      <input v-model="deviceId" placeholder="输入设备唯一标识" />
    </div>

    <!-- 长期密钥交换区域 -->
    <div class="section">
      <h3>1. 长期密钥交换</h3>
      <button @click="generateLongTermKey">生成浏览器长期密钥对</button>
      <div v-if="longTermKeyPair">
        <p>浏览器长期公钥（PEM）：</p>
        <textarea class="key-display" :value="longTermKeyPair.publicKeyPem" readonly rows="4"></textarea>
        <p>浏览器长期公钥（Base64，用于传输）：</p>
        <textarea class="key-display" :value="longTermKeyPair.publicKey" readonly rows="3"></textarea>
      </div>
      <button
          @click="exchangeLongTermKey"
          :disabled="!longTermKeyPair || !deviceId || !accessToken"
      >
        交换长期公钥
      </button>
      <div v-if="serverLongTermEncryptPublicKey" class="response-area">
        <p>服务端返回长期公钥（PEM）：</p>
        <textarea class="key-display" :value="serverLongTermEncryptPublicKey" readonly rows="4"></textarea>
      </div>
    </div>

    <!-- 临时密钥交换区域 -->
    <div class="section">
      <h3>2. 临时密钥交换（ECDHE）</h3>
      <button @click="generateShortTermKey">生成浏览器临时密钥对</button>
      <div v-if="shortTermKeyPair">
        <p>浏览器临时公钥（PEM）：</p>
        <textarea class="key-display" :value="shortTermKeyPair.publicKeyPem" readonly rows="4"></textarea>
        <p>浏览器临时公钥（Base64，用于传输）：</p>
        <textarea class="key-display" :value="shortTermKeyPair.publicKey" readonly rows="3"></textarea>
      </div>
      <button
          @click="exchangeShortTermKey"
          :disabled="!shortTermKeyPair || !deviceId || !serverLongTermEncryptPublicKey || !accessToken"
      >
        交换临时公钥并协商共享密钥
      </button>
      <div v-if="sharedSecret" class="response-area">
        <p>协商出的原始共享密钥（Base64）：</p>
        <textarea class="key-display" :value="rawSharedSecret" readonly rows="2"></textarea>
        <p>派生后的AES密钥（Base64）：</p>
        <textarea class="key-display" :value="sharedSecret" readonly rows="2"></textarea>
      </div>
    </div>

    <!-- 加密业务请求区域 -->
    <div class="section">
      <h3>3. 加密业务请求</h3>
      <div class="input-group">
        <label>请求明文：</label>
        <input v-model="businessText" placeholder="输入要发送的业务数据" />
      </div>
      <button
          @click="sendEncryptedRequest"
          :disabled="!sharedSecret || !deviceId || !businessText || !accessToken"
      >
        发送加密请求
      </button>

      <div v-if="encryptedResponse" class="response-area">
        <p>服务端加密响应（Base64）：</p>
        <textarea class="key-display" :value="encryptedResponse" readonly rows="3"></textarea>
        <p v-if="rawResult">服务端解密响应：<br>{{ rawResult }}</p>
        <p v-if="decryptedResult">解密后结果：{{ decryptedResult }}</p>
      </div>
    </div>

    <!-- 日志区域 -->
    <div class="log-section">
      <h3>操作日志</h3>
      <div class="log-content" v-for="(log, index) in logs" :key="index">{{ log }}</div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'; // 新增：导入全局axios
import api, {getGlobalKeys, setGlobalKeys} from '@/utils/api';
import securityUtils from '@/utils/securityUtils';

export default {
  data() {
    return {
      // 登录相关
      loginUsername: 'client1',
      loginPassword: 'secret1',
      accessToken: localStorage.getItem('accessToken') || '',
      tokenType: localStorage.getItem('tokenType') || '',
      expiresIn: 0,

      // 密钥相关
      deviceId: "device-lhr2j7tme",
      longTermKeyPair: null,
      serverLongTermEncryptPublicKey: '',
      shortTermKeyPair: null,
      rawSharedSecret: '',
      sharedSecret: '',
      decrypting: false,

      // 业务数据
      businessText: '测试加密通信',
      encryptedResponse: '',
      decryptedResult: '',
      rawResult:'',
      logs: [],
      usedNonces: new Set()
    };
  },
  methods: {
    // 登录获取Token（使用原生axios，避免拦截器干扰）
    async login() {
      try {
        this.addLog('开始登录...');
        const authHeader = btoa(`${this.loginUsername}:${this.loginPassword}`);
        // 修复：使用全局axios，避免自定义拦截器干扰
        const response = await axios.post(
            '/oauth2/token', // 确保后端地址正确，若后端端口不是8080需补全（如http://localhost:8080/oauth2/token）
            'grant_type=client_credentials&scope=read write', // 拼接所有scope，与后端客户端配置一致
            {
              headers: {
                'Content-Type': 'application/x-www-form-urlencoded', // 必须是form-urlencoded格式
                'Authorization': `Basic ${authHeader}` // Basic认证头（客户端ID:密码的Base64）
              }
            }
        );

        if (response.data.access_token) {
          this.accessToken = response.data.access_token;
          this.tokenType = response.data.token_type;
          this.expiresIn = response.data.expires_in;
          localStorage.setItem('accessToken', this.accessToken);
          localStorage.setItem('tokenType', this.tokenType);
          this.addLog('登录成功，已获取Token');
        } else {
          this.addLog('登录失败：未返回Token');
        }
      } catch (e) {
        // 增强错误提示，便于排查
        this.addLog(`登录失败：${e.message || '未知错误'}`);
        if (e.response) {
          this.addLog(`错误状态码：${e.response.status}`);
          this.addLog(`错误响应：${JSON.stringify(e.response.data)}`);
        } else {
          console.error('登录请求异常（无响应）：', e); // 打印控制台，辅助排查
        }
      }
    },

    // 注销登录
    logout() {
      this.accessToken = '';
      this.tokenType = '';
      this.expiresIn = 0;
      localStorage.removeItem('accessToken');
      localStorage.removeItem('tokenType');
      setGlobalKeys({ longTermPrivateKey: null, sharedSecret: null }); // 清空密钥
      this.addLog('已注销登录');
    },

    // 添加日志
    addLog(message) {
      this.logs.unshift(`[${new Date().toLocaleTimeString()}] ${message}`);
      if (this.logs.length > 10) this.logs.pop();
    },

    // 生成长期密钥对
    async generateLongTermKey() {
      try {
        if (!window.crypto?.subtle) throw new Error('浏览器不支持Web Crypto API');

        const keyPair = await window.crypto.subtle.generateKey(
            {
              name: "ECDSA",
              namedCurve: "P-256" // 对应后端 ECC_NIST_P256 曲线
            },
            true, // 可提取密钥
            ["sign", "verify"]
        );

        const publicKeyBytes = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
        const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyBytes)));
        const publicKeyPem = securityUtils.arrayBufferToPem(publicKeyBytes, 'PUBLIC KEY');

        this.longTermKeyPair = { privateKey: keyPair.privateKey, publicKey: publicKeyBase64, publicKeyPem };
        setGlobalKeys({ longTermPrivateKey: keyPair.privateKey }); // 保存长期私钥到全局
        this.addLog('浏览器长期RSA密钥对生成成功');
      } catch (e) {
        this.addLog(`长期密钥生成失败：${e.message}`);
      }
    },

    // 交换长期公钥
    async exchangeLongTermKey() {
      try {
        if (!this.longTermKeyPair || !this.deviceId || !this.accessToken) {
          throw new Error('请先生成长期密钥对、输入设备ID并登录');
        }

        this.addLog('开始交换长期公钥...');
        const response = await api.post('/api/security/long-term-key/exchange', {
          deviceId: this.deviceId,
          clientPublicKey: this.longTermKeyPair.publicKey
        });

        if (response.data.code === 0) {
          const serverEncryptPublicKey = response.data.data.serverEncryptPublicKey;

          setGlobalKeys({
            serverLongTermSignPublicKey: response.data.data.serverSignPublicKey // 传入公钥字符串
          });
          this.serverLongTermEncryptPublicKey = securityUtils.base64ToPem(serverEncryptPublicKey, 'PUBLIC KEY');
          this.addLog('长期公钥交换成功');
        } else {
          this.addLog(`交换失败：${response.data.message}`);
        }
      } catch (e) {
        this.addLog(`长期公钥交换异常：${e.message}`);
        if (e.response) this.addLog(`错误响应：${JSON.stringify(e.response.data)}`);
      }
    },

    // 生成临时ECDH密钥对
    async generateShortTermKey() {
      try {
        if (!window.crypto?.subtle) throw new Error('浏览器不支持Web Crypto API');

        const keyPair = await window.crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveBits']
        );

        const publicKeyBytes = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
        const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyBytes)));
        const publicKeyPem = securityUtils.arrayBufferToPem(publicKeyBytes, 'PUBLIC KEY');

        this.shortTermKeyPair = { privateKey: keyPair.privateKey, publicKey: publicKeyBase64, publicKeyPem };
        this.addLog('浏览器临时ECDH密钥对生成成功');
      } catch (e) {
        this.addLog(`临时密钥生成失败：${e.message}`);
      }
    },

    // 交换临时公钥并协商共享密钥
    async exchangeShortTermKey() {
      try {
        if (!this.shortTermKeyPair || !this.deviceId || !this.serverLongTermEncryptPublicKey || !this.accessToken) {
          throw new Error('前置条件不足或未登录');
        }

        this.addLog('开始交换临时公钥...');
        const response = await api.post('/api/security/short-term-key/exchange', {
          deviceId: this.deviceId,
          clientPublicKey: this.shortTermKeyPair.publicKey
        });

        if (response.data.code === 0) {
          const serverPublicKeyPem = response.data.data.serverPublicKey;
          const serverPublicKey = await securityUtils.pemToCryptoKey(
              serverPublicKeyPem,
              'PUBLIC KEY',
              'ECDH'
          );

          // 计算原始共享密钥
          const sharedBits = await window.crypto.subtle.deriveBits(
              { name: 'ECDH', public: serverPublicKey },
              this.shortTermKeyPair.privateKey,
              256
          );
          const sharedSecretRaw = new Uint8Array(sharedBits);
          this.rawSharedSecret = btoa(String.fromCharCode(...sharedSecretRaw));

          // 派生AES密钥
          const aesKey = await securityUtils.hkdfDerive(sharedSecretRaw, 'ecdhe-aes-gcm');
          const aesKeyRaw = await window.crypto.subtle.exportKey('raw', aesKey);
          this.sharedSecret = btoa(String.fromCharCode(...new Uint8Array(aesKeyRaw)));
          setGlobalKeys({ sharedSecret: this.sharedSecret }); // 保存共享密钥到全局

          this.addLog('共享密钥计算成功');
        }
      } catch (e) {
        this.addLog(`临时公钥交换异常：${e.stack}`);
        if (e.response) console.error('后端错误：', e.response.data);
      }
    },
    // 发送加密业务请求（补充加密响应的有效性校验）
    async sendEncryptedRequest() {
      try {
        if (!this.sharedSecret || !this.deviceId || !this.businessText || !this.accessToken) {
          throw new Error('请完成密钥协商、输入请求内容并登录');
        }

        this.addLog('开始加密业务请求...');
        const encryptedText = await securityUtils.encryptData(this.businessText, this.sharedSecret);
        this.addLog("encryptedText:" + encryptedText);

        const response = await api.post('/api/security/business/encrypt', {
          text: encryptedText,
          deviceId: this.deviceId
        });
        if (response.data.code === 0) {
          const encryptedData = response.data.data;
          this.rawResult = await securityUtils.decryptData(encryptedData, getGlobalKeys().sharedSecret);
          // 校验服务端返回的加密数据是否有效
          if (!encryptedData || encryptedData.trim() === '') {
            throw new Error('服务端返回的加密响应为空');
          }
          this.encryptedResponse = encryptedData;
          this.addLog('加密请求发送成功，已获取服务端加密响应');
          // 清空上次解密结果
          this.decryptedResult = '';
          this.rawSharedSecret = '';
        } else {
          this.addLog(`服务端返回错误：${response.data.message}`);
        }
      } catch (e) {
        this.addLog(`业务请求异常：${e.message}`);
        // 出错时清空加密响应，避免无效数据残留
        this.encryptedResponse = '';
        this.decryptedResult = '';
      }
    },
  }
};
</script>

<style>
/* 样式保持不变 */
.security-test-container {
  max-width: 1000px;
  margin: 0 auto;
  padding: 20px;
  font-family: Arial, sans-serif;
}

.section {
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 15px;
  margin-bottom: 20px;
}

.input-group {
  margin: 10px 0;
}

input, textarea {
  width: 100%;
  padding: 8px;
  margin-top: 5px;
  border: 1px solid #ccc;
  border-radius: 4px;
  box-sizing: border-box;
}

.key-display {
  width: 100%;
  background-color: #f5f5f5;
  font-family: monospace;
}

button {
  margin: 10px 0;
  padding: 8px 16px;
  background-color: #42b983;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

button:disabled {
  background-color: #ccc;
  cursor: not-allowed;
}

.response-area {
  margin-top: 10px;
  padding: 10px;
  background-color: #f9f9f9;
  border-radius: 4px;
}

.log-section {
  margin-top: 20px;
  padding: 15px;
  background-color: #f0f0f0;
  border-radius: 8px;
}

.log-content {
  margin: 5px 0;
  font-size: 14px;
  color: #333;
}
</style>