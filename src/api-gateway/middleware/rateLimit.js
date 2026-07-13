'use strict';

const rateLimit = require('express-rate-limit');

// ============================================================================
// Rate Limiting Middleware
// Middleware giới hạn tốc độ truy cập để chống tấn công DDoS và Brute Force.
//
// Nguyên tắc bảo mật:
// - Giới hạn số request theo IP trong một khoảng thời gian
// - Endpoint xác thực (login/register) có giới hạn NGHIÊM NGẶT hơn
//   vì đây là mục tiêu chính của tấn công brute force
// - Endpoint thanh toán có giới hạn riêng phù hợp với lưu lượng thực tế
// ============================================================================

/**
 * Cửa sổ thời gian mặc định: 15 phút (tính bằng millisecond).
 * Sau mỗi 15 phút, bộ đếm request sẽ được reset.
 * @constant {number}
 */
const WINDOW_MS = 15 * 60 * 1000;

/**
 * Hàm tạo thông báo lỗi chuẩn khi vượt quá giới hạn.
 * Tuân theo format response thống nhất của hệ thống.
 *
 * @param {string} type - Loại endpoint bị giới hạn
 * @param {number} retryAfterSeconds - Số giây cần chờ trước khi thử lại
 * @returns {object} Response body chuẩn
 */
const createLimitMessage = (type, retryAfterSeconds) => ({
  success: false,
  error: {
    code: 'RATE_LIMIT_EXCEEDED',
    message: `Quá nhiều yêu cầu từ địa chỉ IP này cho ${type}. Vui lòng thử lại sau ${Math.ceil(retryAfterSeconds / 60)} phút.`,
    type,
    retryAfter: retryAfterSeconds,
  },
});

/**
 * Middleware giới hạn tốc độ TỔNG QUÁT (General Rate Limiter).
 * Áp dụng cho tất cả các route của API Gateway.
 *
 * Cấu hình:
 * - Cửa sổ: 15 phút
 * - Tối đa: 100 request / IP / cửa sổ
 * - Header: Trả về RateLimit-* headers theo draft-ietf-httpapi-ratelimit-headers
 *
 * @type {import('express-rate-limit').RateLimitRequestHandler}
 */
const generalLimiter = rateLimit({
  // Khoảng thời gian cửa sổ: 15 phút
  windowMs: WINDOW_MS,

  // Số request tối đa cho mỗi IP trong cửa sổ thời gian
  // 100 request / 15 phút là mức hợp lý cho API tổng quát
  max: 100,

  // Chuẩn hóa response khi vượt giới hạn
  message: createLimitMessage('API chung', WINDOW_MS / 1000),

  // Trả về headers RateLimit để client biết còn bao nhiêu request
  // X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
  standardHeaders: true,

  // Tắt header X-RateLimit-* cũ (legacy), chỉ dùng chuẩn mới
  legacyHeaders: false,

  // Hàm xác định key để nhóm request - mặc định theo IP
  // Trong production với reverse proxy, cần cấu hình trust proxy
  keyGenerator: (req) => {
    // Ưu tiên X-Forwarded-For khi đứng sau load balancer / reverse proxy
    return req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  },

  // Handler tùy chỉnh khi vượt giới hạn
  handler: (req, res) => {
    // Ghi log cảnh báo - có thể là dấu hiệu tấn công DDoS
    console.warn(
      `[RATE-LIMIT] Vượt giới hạn tổng quát | IP: ${req.ip} | Path: ${req.path}`
    );

    res.status(429).json(createLimitMessage('API chung', WINDOW_MS / 1000));
  },
});

/**
 * Middleware giới hạn tốc độ cho endpoint XÁC THỰC (Auth Rate Limiter).
 * NGHIÊM NGẶT hơn vì đây là mục tiêu chính của tấn công brute force.
 *
 * Cấu hình:
 * - Cửa sổ: 15 phút
 * - Tối đa: 20 request / IP / cửa sổ (nghiêm ngặt hơn 5x so với tổng quát)
 * - Lý do: Người dùng bình thường không cần đăng nhập > 20 lần trong 15 phút
 *   Nếu vượt ngưỡng này, rất có thể đang bị tấn công brute force mật khẩu
 *
 * @type {import('express-rate-limit').RateLimitRequestHandler}
 */
const authLimiter = rateLimit({
  windowMs: WINDOW_MS,

  // Chỉ 20 request / 15 phút - rất nghiêm ngặt
  // Tấn công brute force cần hàng nghìn lần thử → bị chặn ngay
  max: 20,

  message: createLimitMessage('xác thực (login/register)', WINDOW_MS / 1000),

  standardHeaders: true,
  legacyHeaders: false,

  // Bỏ qua các request thành công - chỉ đếm request thất bại
  // Điều này giúp người dùng hợp lệ không bị ảnh hưởng
  skipSuccessfulRequests: false,

  keyGenerator: (req) => {
    return req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  },

  handler: (req, res) => {
    // Ghi log cảnh báo mức CAO - có thể là tấn công brute force
    console.error(
      `[RATE-LIMIT] ⚠️  Vượt giới hạn XÁC THỰC | IP: ${req.ip} | Path: ${req.path} | ` +
      `Có thể là tấn công brute force!`
    );

    res.status(429).json(
      createLimitMessage('xác thực (login/register)', WINDOW_MS / 1000)
    );
  },
});

/**
 * Middleware giới hạn tốc độ cho endpoint THANH TOÁN (Payment Rate Limiter).
 * Giới hạn vừa phải, cân bằng giữa bảo mật và trải nghiệm người dùng.
 *
 * Cấu hình:
 * - Cửa sổ: 15 phút
 * - Tối đa: 50 request / IP / cửa sổ
 * - Lý do: Giao dịch thanh toán cần được bảo vệ khỏi tấn công replay
 *   và lạm dụng, nhưng merchant có thể cần xử lý nhiều giao dịch
 *
 * @type {import('express-rate-limit').RateLimitRequestHandler}
 */
const paymentLimiter = rateLimit({
  windowMs: WINDOW_MS,

  // 50 request / 15 phút - vừa phải cho giao dịch thanh toán
  max: 50,

  message: createLimitMessage('thanh toán', WINDOW_MS / 1000),

  standardHeaders: true,
  legacyHeaders: false,

  keyGenerator: (req) => {
    // Đối với payment, kết hợp IP + User ID (nếu có) để giới hạn chính xác hơn
    // Tránh trường hợp nhiều user dùng chung IP (NAT) bị ảnh hưởng lẫn nhau
    const userId = req.user ? req.user.id : 'anonymous';
    return `${req.ip}_${userId}`;
  },

  handler: (req, res) => {
    console.error(
      `[RATE-LIMIT] ⚠️  Vượt giới hạn THANH TOÁN | IP: ${req.ip} | ` +
      `User: ${req.user ? req.user.id : 'N/A'} | Path: ${req.path}`
    );

    res.status(429).json(createLimitMessage('thanh toán', WINDOW_MS / 1000));
  },
});

module.exports = {
  generalLimiter,
  authLimiter,
  paymentLimiter,
};
