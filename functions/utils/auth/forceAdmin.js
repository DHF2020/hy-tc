/**
 * 强制管理端登录（无状态直通）
 *
 * 目的：在「数据库没绑定 / 里面存着旧密码 / 会话表读不到」等任何情况下，
 *       只要在登录页输入写死的用户名 + 密码，就直接进后台，绝不返回服务器错误。
 *
 * 原理：登录成功时下发一个固定值的 HttpOnly Cookie，之后所有鉴权入口
 *       （sessionCheck / authCore.authenticate / sessionManager.validateSession）
 *       先认这个 Cookie，命中就直接判定为管理员，全程不碰数据库。
 *
 * 注意：这是一个「后门」性质的文件，代码公开即可被绕过，
 *       只适合自用 / 内网 / 临时救急场景。
 */

// ====== 登录凭据 ======
export const FORCE_ADMIN_USERNAME = '2233';
export const FORCE_ADMIN_PASSWORD = '472584105918';

// ====== 无状态会话 Cookie ======
export const FORCE_COOKIE_NAME = 'force_admin_session';
const FORCE_COOKIE_VALUE = 'f7a1c9d4e6b80712a2b3c4d5e6f708192a3b4c5d';
const DEFAULT_MAX_AGE = 30 * 24 * 3600; // 30 天

/**
 * 从请求头里读取某个 Cookie 的值
 * @param {Request} request
 * @param {string} name
 * @returns {string}
 */
export function readCookie(request, name) {
    const header = request.headers.get('Cookie') || '';
    for (const part of header.split(';')) {
        const idx = part.indexOf('=');
        if (idx === -1) continue;
        if (part.slice(0, idx).trim() === name) {
            return part.slice(idx + 1).trim();
        }
    }
    return '';
}

/**
 * 当前请求是否已经持有强制登录 Cookie
 * @param {Request} request
 * @returns {boolean}
 */
export function hasForceSession(request) {
    return readCookie(request, FORCE_COOKIE_NAME) === FORCE_COOKIE_VALUE;
}

/**
 * 构造下发用的 Set-Cookie 字符串
 * @param {Request} request - 用来判断是否走 https
 * @param {number} [maxAgeSeconds]
 * @returns {string}
 */
export function buildForceCookie(request, maxAgeSeconds = DEFAULT_MAX_AGE) {
    const isHttps = new URL(request.url).protocol === 'https:';
    const parts = [
        `${FORCE_COOKIE_NAME}=${FORCE_COOKIE_VALUE}`,
        'Path=/',
        `Max-Age=${maxAgeSeconds}`,
        'HttpOnly',
        'SameSite=Lax',
    ];
    if (isHttps) parts.push('Secure');
    return parts.join('; ');
}

/**
 * 构造登出用的 Set-Cookie 字符串
 * @param {Request} request
 * @returns {string}
 */
export function clearForceCookie(request) {
    return buildForceCookie(request, 0);
}
