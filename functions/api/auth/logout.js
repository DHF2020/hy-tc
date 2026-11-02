import { destroySession } from "../../utils/auth/sessionManager.js";
import { clearForceCookie } from "../../utils/auth/forceAdmin.js";

export async function onRequestPost(context) {
    const { request, env } = context;

    // 从请求体中获取要登出的类型，默认清除所有
    let authType = null;
    try {
        const body = await request.json();
        authType = body.authType || null;
    } catch {
        // 没有请求体，清除所有
    }

    const headers = new Headers();

    // 清除强制登录 Cookie（数据库不可用时也能正常登出）
    headers.append('Set-Cookie', clearForceCookie(request));

    try {
        const result = await destroySession(env, request, authType);

        // result 可能是单个字符串或数组
        if (Array.isArray(result)) {
            result.forEach(cookie => headers.append('Set-Cookie', cookie));
        } else {
            headers.append('Set-Cookie', result);
        }
    } catch (error) {
        console.warn('logout: session store unavailable:', error && error.message);
    }

    return new Response('Logged out', {
        status: 200,
        headers,
    });
}
