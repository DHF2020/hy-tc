import { checkDatabaseConfig } from '../utils/middleware';

// 登录 / 登出 / 会话检查这几个接口本身不需要数据库（强制登录版靠无状态 Cookie），
// 如果也被「数据库未配置 → 500」挡住，登录页会直接显示「服务器错误」，连错在哪都看不出来。
// 所以这里对它们放行，其余 /api/* 仍然要求先配置 KV 或 D1。
const AUTH_ENDPOINTS = new Set([
    '/api/auth/adminLogin',
    '/api/auth/login',
    '/api/auth/logout',
    '/api/auth/sessionCheck',
]);

async function databaseGate(context) {
    const path = new URL(context.request.url).pathname.replace(/\/+$/, '') || '/';
    if (AUTH_ENDPOINTS.has(path)) {
        return context.next();
    }
    return checkDatabaseConfig(context);
}

export const onRequest = [databaseGate];
