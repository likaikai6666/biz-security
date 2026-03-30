import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import vueDevTools from 'vite-plugin-vue-devtools'

export default defineConfig({
    plugins: [
        vue(),
        vueDevTools(),
    ],
    resolve: {
        alias: {
            '@': fileURLToPath(new URL('./src', import.meta.url))
        },
    },
    server: {
        proxy: {
            // 代理所有 /api 开头的请求到后端
            '/api': {
                target: 'http://localhost:8080',
                changeOrigin: true,
                withCredentials: true // 允许携带认证信息
            },
            // 代理认证相关路径（如登录、OAuth2）
            '/oauth2': {
                target: 'http://localhost:8080',
                changeOrigin: true,
                withCredentials: true
            },
            '/login': {
                target: 'http://localhost:8080',
                changeOrigin: true,
                withCredentials: true
            }
        }
    }
})