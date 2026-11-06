// 自定义适配器通过请求上下文声明平台；Pages 使用原生 Functions 入口。
// 覆盖同名环境变量，避免用户配置将 Pages/Workers 误判为 Node。
//
// ============================================================================
// 站点隐藏闸门
// 环境变量 GATE_SECRET 为空/未配置时：闸门完全不生效，行为与改造前完全一致。
// 配置 GATE_SECRET 后：访问 https://<域名>/?k=<GATE_SECRET> 一次即可拿到放行 Cookie，
// 此后该浏览器可以正常打开后台；其他人拿不到 Cookie，一律 400 malformed URL。
// /file 前缀永远放行，图片外链不受影响。
// ============================================================================

// 放行 Cookie 名（下划线开头，避免和业务 Cookie 冲突）
const GATE_COOKIE = '__gate';

// 永远放行的路径前缀（图片外链）。如需公开随机图，把 '/random' 加进来即可。
const PUBLIC_PREFIXES = ['/file'];

// 放行 Cookie 有效期：1 年（秒）
const GATE_MAX_AGE = 31536000;

// 令牌缓存：同一个 isolate 内只算一次 SHA-256
let cachedSecret = null;
let cachedToken = null;

/**
 * 计算十六进制 SHA-256
 * @param {string} text
 * @returns {Promise<string>}
 */
async function sha256Hex(text) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(digest))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * 把 GATE_SECRET 折算成 Cookie 里真正存放的令牌
 * @param {string} secret
 * @returns {Promise<string>}
 */
async function gateToken(secret) {
    if (cachedSecret === secret && cachedToken) {
        return cachedToken;
    }
    cachedToken = await sha256Hex('imgbed-gate:' + secret);
    cachedSecret = secret;
    return cachedToken;
}

/**
 * 读取指定 Cookie
 * @param {Request} request
 * @param {string} name
 * @returns {string|null}
 */
function readCookie(request, name) {
    const header = request.headers.get('Cookie');
    if (!header) return null;
    const match = header.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
    return match ? match[1] : null;
}

/**
 * 定长时间比较，避免逐字符短路泄露前缀
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function safeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) {
        return false;
    }
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return diff === 0;
}

/**
 * 复刻 Cloudflare Images 的兜底错误：body 恰好 13 字节、不带换行
 * @returns {Response}
 */
function malformedURLResponse() {
    return new Response('malformed URL', {
        status: 400,
        headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Content-Security-Policy': "default-src 'none'",
            'X-Content-Type-Options': 'nosniff',
            // 400 不允许被浏览器缓存，否则第一次进来的访客会被一直挡到缓存过期
            'Cache-Control': 'no-store',
        },
    });
}

/**
 * 路径是否在公开前缀内（按段匹配，/filex 不算 /file）
 * @param {string} pathname
 * @returns {boolean}
 */
function isPublicPath(pathname) {
    return PUBLIC_PREFIXES.some(prefix =>
        pathname === prefix || pathname.startsWith(prefix + '/')
    );
}

/**
 * 闸门主逻辑：拦下就返回 Response，放行就返回 null
 * @param {Object} context
 * @returns {Promise<Response|null>}
 */
async function enforceGate(context) {
    const { request, env } = context;

    const secret = env && env.GATE_SECRET ? String(env.GATE_SECRET).trim() : '';
    if (!secret) {
        return null; // 没配置密钥 = 闸门关闭
    }

    const url = new URL(request.url);

    // 1) 图片外链永远放行
    if (isPublicPath(url.pathname)) {
        return null;
    }

    const token = await gateToken(secret);

    // 2) 入口：?k=密钥 或 请求头 x-gate
    const provided = url.searchParams.get('k') || request.headers.get('x-gate');
    if (provided && safeEqual(provided, secret)) {
        url.searchParams.delete('k');
        const search = url.searchParams.toString();
        const target = url.pathname + (search ? '?' + search : '');
        // 线上是 https 就带 Secure；本地 wrangler dev 的 http 不加，方便调试
        const secureAttr = url.protocol === 'https:' ? '; Secure' : '';
        return new Response(null, {
            status: 302,
            headers: {
                'Location': target || '/',
                'Set-Cookie': `${GATE_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${GATE_MAX_AGE}${secureAttr}`,
                'Cache-Control': 'no-store',
            },
        });
    }

    // 3) 已经过闸门
    if (readCookie(request, GATE_COOKIE) === token) {
        return null;
    }

    // 4) 其余全部拦掉
    return malformedURLResponse();
}

export async function onRequest(context) {
    const runtime = context.data.serverRuntime;
    context.env.SERVER_RUNTIME = runtime === 'node' || runtime === 'worker' ? runtime : 'pages';

    const blocked = await enforceGate(context);
    if (blocked) {
        return blocked;
    }

    return context.next();
}
