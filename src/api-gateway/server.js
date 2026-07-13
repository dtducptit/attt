'use strict';

// Tải biến môi trường từ file .env (phải gọi đầu tiên)
require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const { createProxyMiddleware } = require('http-proxy-middleware');

// Import middleware bảo mật tùy chỉnh
const { authenticateJWT } = require('./middleware/auth');
const { generalLimiter, authLimiter, paymentLimiter } = require('./middleware/rateLimit');

// ============================================================================
// API Gateway Server
// Cổng API trung tâm cho hệ thống thanh toán đa lớp bảo mật.
//
// Vai trò của API Gateway trong kiến trúc microservice:
// 1. Điểm vào duy nhất (Single Entry Point) - giảm bề mặt tấn công
// 2. Xác thực tập trung (Centralized Authentication) - JWT validation
// 3. Giới hạn tốc độ (Rate Limiting) - chống DDoS/Brute Force
// 4. Proxy routing - điều hướng request đến đúng service
// 5. Audit logging - ghi nhật ký kiểm toán cho mọi request
// ============================================================================

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================================
// 1. HELMET - Bảo mật HTTP Headers
// Thiết lập các header bảo mật theo khuyến nghị OWASP:
// - Content-Security-Policy: Chống XSS
// - X-Content-Type-Options: Chống MIME sniffing
// - X-Frame-Options: Chống Clickjacking
// - Strict-Transport-Security: Bắt buộc HTTPS
// - X-XSS-Protection: Bộ lọc XSS bổ sung
// ============================================================================
app.use(helmet({
  // Chính sách bảo mật nội dung - chặn inline scripts để chống XSS
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'"],
      connectSrc: ["'self'"],
      // Không cho phép nhúng trong frame từ domain khác
      frameAncestors: ["'none'"],
    },
  },
  // Bắt buộc HTTPS trong 1 năm, bao gồm subdomain
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
}));

// ============================================================================
// 2. CORS - Cross-Origin Resource Sharing
// Kiểm soát nguồn gốc request được phép truy cập API.
// Chỉ cho phép domain đã đăng ký - chống CSRF từ domain lạ.
// ============================================================================
const corsOptions = {
  // Danh sách domain được phép - trong production lấy từ biến môi trường
  origin: process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['http://localhost:3000'],

  // Chỉ cho phép các HTTP method cần thiết
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],

  // Header được phép gửi từ client
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],

  // Cho phép gửi cookie/credentials cross-origin
  credentials: true,

  // Cache preflight response trong 10 phút
  maxAge: 600,
};
app.use(cors(corsOptions));

// ============================================================================
// 3. MORGAN - HTTP Request Logging
// Ghi log tất cả HTTP request để phục vụ giám sát và điều tra sự cố.
// Trong production sử dụng format 'combined' để có đầy đủ thông tin.
// ============================================================================
const morganFormat = process.env.NODE_ENV === 'production' ? 'combined' : 'dev';
app.use(morgan(morganFormat, {
  // Bỏ qua health check để tránh spam log
  skip: (req) => req.path === '/health',
}));

// ============================================================================
// 4. BODY PARSER - Giới hạn kích thước request body
// Ngăn chặn tấn công payload quá lớn (Large Payload Attack)
// ============================================================================
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ============================================================================
// 5. RATE LIMITING TỔNG QUÁT
// Áp dụng giới hạn chung cho tất cả các route
// ============================================================================
app.use(generalLimiter);

// ============================================================================
// 6. AUDIT LOGGING MIDDLEWARE
// Ghi nhật ký kiểm toán cho MỌI request đi qua Gateway.
// Thông tin được ghi: thời gian, phương thức, đường dẫn, user, IP, status code.
//
// Đây là yêu cầu bắt buộc trong PCI DSS (Payment Card Industry Data Security Standard)
// để đảm bảo truy vết được mọi hoạt động trên hệ thống thanh toán.
// ============================================================================

/**
 * Middleware ghi nhật ký kiểm toán (Audit Log).
 * Ghi lại thông tin chi tiết về mọi request để phục vụ:
 * - Phát hiện xâm nhập (Intrusion Detection)
 * - Điều tra sự cố bảo mật (Forensic Analysis)
 * - Tuân thủ quy định PCI DSS
 *
 * @param {import('express').Request} req - Express request object
 * @param {import('express').Response} res - Express response object
 * @param {import('express').NextFunction} next - Express next middleware
 */
const auditLogger = (req, res, next) => {
  // Ghi nhận thời điểm bắt đầu xử lý request
  const startTime = Date.now();

  // Lắng nghe sự kiện 'finish' để ghi log SAU KHI response được gửi
  // Điều này đảm bảo có được status code chính xác
  res.on('finish', () => {
    const duration = Date.now() - startTime;

    const auditEntry = {
      // Thời gian theo chuẩn ISO 8601 với timezone
      timestamp: new Date().toISOString(),

      // Thông tin request
      method: req.method,
      path: req.originalUrl || req.path,
      query: Object.keys(req.query).length > 0 ? req.query : undefined,

      // Thông tin người dùng (nếu đã xác thực)
      user: req.user ? {
        id: req.user.id,
        role: req.user.role,
        sessionId: req.user.sessionId,
      } : null,

      // Thông tin mạng
      ip: req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],

      // Thông tin response
      statusCode: res.statusCode,
      duration: `${duration}ms`,

      // Request ID để truy vết xuyên suốt các service (Distributed Tracing)
      requestId: req.headers['x-request-id'] || 'N/A',
    };

    // Phân loại log theo mức độ dựa trên status code
    if (res.statusCode >= 500) {
      // Lỗi server - cần điều tra ngay
      console.error('[AUDIT] ❌ SERVER ERROR:', JSON.stringify(auditEntry));
    } else if (res.statusCode >= 400) {
      // Lỗi client - có thể là dấu hiệu tấn công
      console.warn('[AUDIT] ⚠️  CLIENT ERROR:', JSON.stringify(auditEntry));
    } else {
      // Request thành công
      console.info('[AUDIT] ✅', JSON.stringify(auditEntry));
    }
  });

  next();
};

app.use(auditLogger);

// ============================================================================
// 7. HEALTH CHECK ENDPOINT
// Endpoint kiểm tra sức khỏe Gateway - dùng cho Kubernetes probes.
// KHÔNG yêu cầu xác thực vì K8s cần truy cập trực tiếp.
// ============================================================================

/**
 * GET /health
 * Health check endpoint cho Kubernetes liveness/readiness probes.
 * Trả về trạng thái hoạt động của API Gateway.
 */
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    service: 'api-gateway',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage().heapUsed,
  });
});

// ============================================================================
// 8. PROXY ROUTES
// Điều hướng request đến các microservice tương ứng.
//
// Nguyên tắc routing:
// - /api/auth/*     → auth-service:3001    (KHÔNG cần JWT cho login/register)
// - /api/payments/* → payment-service:3002  (BẮT BUỘC JWT)
//
// Lý do tách biệt:
// - Auth service phải public để người dùng đăng nhập
// - Payment service phải được bảo vệ bởi JWT để đảm bảo
//   chỉ người dùng đã xác thực mới thao tác được
// ============================================================================

// URL các microservice - lấy từ biến môi trường hoặc dùng tên DNS nội bộ K8s
const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://auth-service-svc:3001';
const PAYMENT_SERVICE_URL = process.env.PAYMENT_SERVICE_URL || 'http://payment-service-svc:3002';

/**
 * Proxy đến Auth Service (/api/auth/*)
 *
 * KHÔNG yêu cầu JWT vì:
 * - /api/auth/login: Người dùng chưa có token, cần đăng nhập để lấy token
 * - /api/auth/register: Người dùng mới chưa có tài khoản
 * - /api/auth/refresh: Dùng refresh token, không cần access token
 *
 * Tuy nhiên VẪN áp dụng:
 * - Rate limiting nghiêm ngặt (authLimiter) để chống brute force
 * - Helmet headers để bảo vệ response
 * - Audit logging để ghi nhật ký
 */
app.use(
  '/api/auth',
  authLimiter, // Giới hạn 20 request / 15 phút - rất nghiêm ngặt
  createProxyMiddleware({
    target: AUTH_SERVICE_URL,
    changeOrigin: true,
    // Ghi đè đường dẫn - bỏ prefix /api/auth
    pathRewrite: {
      '^/api/auth': '/auth',
    },
    // Truyền header X-Forwarded-* để service biết IP gốc của client
    xfwd: true,
    // Xử lý lỗi proxy - khi auth-service không phản hồi
    onError: (err, req, res) => {
      console.error(`[PROXY] Lỗi kết nối đến Auth Service: ${err.message}`);
      res.status(502).json({
        success: false,
        error: {
          code: 'SERVICE_UNAVAILABLE',
          message: 'Dịch vụ xác thực tạm thời không khả dụng. Vui lòng thử lại sau.',
        },
      });
    },
    // Log proxy request
    onProxyReq: (proxyReq, req) => {
      console.info(`[PROXY] → Auth Service | ${req.method} ${req.originalUrl}`);
    },
  })
);

/**
 * Proxy đến Payment Service (/api/payments/*)
 *
 * BẮT BUỘC JWT vì:
 * - Mọi thao tác thanh toán phải xác minh danh tính người dùng
 * - Cần biết user ID để xác định quyền sở hữu giao dịch
 * - Tuân thủ PCI DSS: "Restrict access to cardholder data by business need to know"
 *
 * Pipeline middleware:
 * 1. paymentLimiter: Giới hạn 50 request / 15 phút
 * 2. authenticateJWT: Xác minh JWT token → gắn req.user
 * 3. createProxyMiddleware: Chuyển tiếp đến payment-service
 */
app.use(
  '/api/payments',
  paymentLimiter, // Giới hạn 50 request / 15 phút
  authenticateJWT, // BẮT BUỘC - xác thực JWT trước khi proxy
  createProxyMiddleware({
    target: PAYMENT_SERVICE_URL,
    changeOrigin: true,
    pathRewrite: {
      '^/api/payments': '/payments',
    },
    xfwd: true,
    // Truyền thông tin user đã xác thực đến payment-service qua header
    // Payment service KHÔNG cần xác thực lại JWT, tin tưởng Gateway
    onProxyReq: (proxyReq, req) => {
      if (req.user) {
        // Truyền thông tin user qua header nội bộ
        // Các header X-User-* chỉ được trust trong mạng nội bộ K8s
        proxyReq.setHeader('X-User-Id', req.user.id);
        proxyReq.setHeader('X-User-Role', req.user.role);
        proxyReq.setHeader('X-User-Email', req.user.email || '');
      }
      console.info(
        `[PROXY] → Payment Service | ${req.method} ${req.originalUrl} | User: ${req.user ? req.user.id : 'N/A'}`
      );
    },
    onError: (err, req, res) => {
      console.error(`[PROXY] Lỗi kết nối đến Payment Service: ${err.message}`);
      res.status(502).json({
        success: false,
        error: {
          code: 'SERVICE_UNAVAILABLE',
          message: 'Dịch vụ thanh toán tạm thời không khả dụng. Vui lòng thử lại sau.',
        },
      });
    },
  })
);

// ============================================================================
// 9. XỬ LÝ ROUTE KHÔNG TỒN TẠI (404)
// Trả về lỗi 404 cho các đường dẫn không được định nghĩa
// ============================================================================
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: {
      code: 'ROUTE_NOT_FOUND',
      message: `Đường dẫn ${req.method} ${req.originalUrl} không tồn tại.`,
    },
  });
});

// ============================================================================
// 10. XỬ LÝ LỖI TOÀN CỤC (Global Error Handler)
// Bắt tất cả lỗi không được xử lý ở middleware/route cụ thể.
// QUAN TRỌNG: Không tiết lộ stack trace trong production!
// ============================================================================

/**
 * Global error handler middleware.
 * Đảm bảo không tiết lộ thông tin nhạy cảm trong response lỗi.
 *
 * @param {Error} err - Error object
 * @param {import('express').Request} req - Express request
 * @param {import('express').Response} res - Express response
 * @param {import('express').NextFunction} _next - Express next (bắt buộc 4 params)
 */
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  console.error('[ERROR] Lỗi không xử lý:', {
    message: err.message,
    stack: process.env.NODE_ENV === 'production' ? undefined : err.stack,
    path: req.path,
    method: req.method,
  });

  res.status(err.status || 500).json({
    success: false,
    error: {
      code: 'INTERNAL_SERVER_ERROR',
      message: process.env.NODE_ENV === 'production'
        ? 'Lỗi hệ thống. Vui lòng thử lại sau.'
        : err.message,
    },
  });
});

// ============================================================================
// 11. KHỞI ĐỘNG SERVER
// ============================================================================
app.listen(PORT, '0.0.0.0', () => {
  console.info('═══════════════════════════════════════════════════════════');
  console.info(`  🚀 API Gateway đang chạy tại cổng ${PORT}`);
  console.info(`  🔐 Chế độ: ${process.env.NODE_ENV || 'development'}`);
  console.info(`  📡 Auth Service: ${AUTH_SERVICE_URL}`);
  console.info(`  💳 Payment Service: ${PAYMENT_SERVICE_URL}`);
  console.info('═══════════════════════════════════════════════════════════');
});

module.exports = app;
