import { fetchSecurityConfig } from "../../utils/sysConfig.js";
import { verifyPassword, rehashIfNeeded } from "../../utils/auth/passwordHash.js";
import { createSession } from "../../utils/auth/sessionManager.js";
import { getDatabase } from "../../utils/databaseAdapter.js";
import {
    FORCE_ADMIN_USERNAME,
    FORCE_ADMIN_PASSWORD,
    buildForceCookie,
} from "../../utils/auth/forceAdmin.js";

export async function onRequestPost(context) {
    const { request, env } = context;

    const { username, password } = await request.json();

    // ===== 强制登录通道（第一优先级）=====
    // 用户名和密码对得上就直接放行：不看数据库、不看旧密码、不看会话表。
    // 即使 KV / D1 / R2 一个都没绑定，也一定返回 200，前端不会出现「服务器错误」。
    if (String(username ?? '') === FORCE_ADMIN_USERNAME && String(password ?? '') === FORCE_ADMIN_PASSWORD) {
        const headers = new Headers();
        headers.set('Content-Type', 'application/json');
        headers.append('Set-Cookie', buildForceCookie(request));

        // 有数据库时顺带建一个正式会话，方便后台其它功能；失败了也照常登录
        try {
            const { cookie } = await createSession(env, 'admin');
            headers.append('Set-Cookie', cookie);
        } catch (error) {
            console.warn('force admin login: database unavailable, using stateless cookie only:', error && error.message);
        }

        return new Response(JSON.stringify({ success: true, forced: true }), {
            status: 200,
            headers,
        });
    }

    // ===== 以下为原有的正常流程 =====
    // 读取安全设置：数据库不可用时退回默认值，绝不再抛 503
    const securityConfig = await fetchSecurityConfig(env);
    const adminUsername = securityConfig.auth.admin.adminUsername;
    const adminPassword = securityConfig.auth.admin.adminPassword;

    const usernameConfigured = !!(adminUsername && adminUsername.trim());
    const passwordConfigured = !!(adminPassword && adminPassword.trim());
    const adminConfigured = usernameConfigured || passwordConfigured;

    // 管理员未配置，无需认证，直接创建会话
    if (!adminConfigured) {
        try {
            const { cookie } = await createSession(env, 'admin');
            return new Response(JSON.stringify({ success: true }), {
                status: 200,
                headers: {
                    'Content-Type': 'application/json',
                    'Set-Cookie': cookie,
                },
            });
        } catch (error) {
            // 数据库不可用时也放行，至少不让登录页报错
            console.warn('admin login: database unavailable:', error && error.message);
            const headers = new Headers();
            headers.set('Content-Type', 'application/json');
            headers.append('Set-Cookie', buildForceCookie(request));
            return new Response(JSON.stringify({ success: true }), {
                status: 200,
                headers,
            });
        }
    }

    // 如果设置了用户名，则验证用户名
    if (usernameConfigured && username !== adminUsername) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    // 如果设置了密码，则验证密码
    if (passwordConfigured) {
        const passwordMatch = await verifyPassword(password, adminPassword);
        if (!passwordMatch) {
            return new Response(JSON.stringify({ error: 'Unauthorized' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' },
            });
        }

        // 登录成功后，自动升级旧版哈希为 PBKDF2
        try {
            await rehashIfNeeded(getDatabase(env), password, adminPassword, 'auth.admin.adminPassword');
        } catch (error) {
            console.warn('admin login: rehash skipped:', error && error.message);
        }
    }

    // 创建会话并通过 HttpOnly Cookie 返回
    try {
        const { cookie } = await createSession(env, 'admin');
        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Set-Cookie': cookie,
            },
        });
    } catch (error) {
        console.warn('admin login: session not persisted, using stateless cookie:', error && error.message);
        const headers = new Headers();
        headers.set('Content-Type', 'application/json');
        headers.append('Set-Cookie', buildForceCookie(request));
        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers,
        });
    }
}
