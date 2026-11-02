import { validateAnySession } from "../../utils/auth/sessionManager.js";
import { fetchSecurityConfig } from "../../utils/sysConfig.js";
import { hasForceSession } from "../../utils/auth/forceAdmin.js";

/**
 * 会话检查接口
 * 用于前端路由守卫检查当前会话是否有效
 * 同时返回各端是否需要认证
 */
export async function onRequestGet(context) {
    const { request, env } = context;

    // 强制登录通道：持有强制 Cookie 直接判定为已登录管理员，不读数据库
    if (hasForceSession(request)) {
        return new Response(JSON.stringify({
            valid: true,
            authType: 'admin',
            adminRequired: true,
            userRequired: false,
        }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    // 读取安全配置，判断是否需要认证（数据库不可用时退回默认值，不返回 503）
    let securityConfig;
    try {
        securityConfig = await fetchSecurityConfig(env, { throwOnError: true });
    } catch (error) {
        console.error('Session check: security config could not be loaded, fallback to empty config:', error && error.message);
        securityConfig = { auth: { user: { authCode: '' }, admin: { adminUsername: '', adminPassword: '' } } };
    }
    const adminUsername = securityConfig.auth.admin.adminUsername;
    const adminPassword = securityConfig.auth.admin.adminPassword;
    const userAuthCode = securityConfig.auth.user.authCode;

    const adminRequired = !!(adminUsername && adminUsername.trim()) || !!(adminPassword && adminPassword.trim());
    const userRequired = !!(userAuthCode && userAuthCode.trim());

    // 检查会话（数据库不可用时按未登录处理，不抛错）
    let sessionResult = { valid: false };
    try {
        sessionResult = await validateAnySession(env, request);
    } catch (error) {
        console.warn('Session check: session store unavailable:', error && error.message);
    }
    if (sessionResult.valid) {
        return new Response(JSON.stringify({
            valid: true,
            authType: sessionResult.session.authType,
            adminRequired,
            userRequired,
        }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    return new Response(JSON.stringify({
        valid: false,
        adminRequired,
        userRequired,
    }), {
        status: 200, // 不再返回 401，让前端根据字段判断
        headers: { 'Content-Type': 'application/json' },
    });
}
