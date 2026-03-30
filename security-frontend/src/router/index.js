import { createRouter, createWebHistory } from 'vue-router'
import SecurityTest from '../views/SecurityTest.vue'

const router = createRouter({
    history: createWebHistory(import.meta.env.BASE_URL),
    routes: [
        {
            path: '/',
            name: 'security-test',
            component: SecurityTest
        }
    ]
})

export default router