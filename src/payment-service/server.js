'use strict';

/**
 * @fileoverview Entry point cho Payment Service.
 *
 * Server Express với các lớp bảo mật:
 *   1. Helmet: thiết lập HTTP security headers (CSP, HSTS, X-Frame-Options, ...)
 *   2. CORS: chỉ cho phép origin đã đăng ký
 *   3. Morgan: ghi log HTTP request (audit trail)
 *   4. Rate Limiting: (tích hợp ở Gateway) ngăn brute-force/DoS
 *   5. Input size limit: giới hạn body size → ngăn payload quá lớn
 *
 * @module payment-service/server
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const { Sequelize } = require('sequelize');

// Cấu hình tập trung
const config = require('../shared/config');

// Controller
const paymentController = require('./controllers/paymentController');

// ===========================================================================
// KHỞI TẠO DATABASE (Sequelize + PostgreSQL)
// ===========================================================================

/**
 * Tạo instance Sequelize kết nối đến database Payment.
 *
 * Cấu hình pool connection để tái sử dụng kết nối,
 * tránh overhead tạo kết nối mới cho mỗi request.
 */
const sequelize = new Sequelize(
  config.database.PAYMENT_DB,
  config.database.USERNAME,
  config.database.PASSWORD,
  {
    host: config.database.HOST,
    port: config.database.PORT,
    dialect: config.database.DIALECT,
    logging: config.database.LOGGING,
    pool: {
      max: config.database.POOL.MAX,
      min: config.database.POOL.MIN,
      acquire: config.database.POOL.ACQUIRE,
      idle: config.database.POOL.IDLE,
    },
    dialectOptions: config.database.SSL
      ? { ssl: config.database.SSL }
      : {},
  }
);

// Khởi tạo model Transaction
const Transaction = require('./models/transaction')(sequelize);

// ===========================================================================
// KHỞI TẠO EXPRESS APP
// ===========================================================================

const app = express();

// ---------------------------------------------------------------------------
// MIDDLEWARE BẢO MẬT
// ---------------------------------------------------------------------------

/**
 * Helmet thiết lập các HTTP response header bảo mật:
 *   - Content-Security-Policy: ngăn XSS, data injection
 *   - X-Content-Type-Options: nosniff — ngăn MIME type sniffing
 *   - X-Frame-Options: DENY — ngăn clickjacking
 *   - Strict-Transport-Security: bắt buộc HTTPS
 *   - X-XSS-Protection: kích hoạt bộ lọc XSS của trình duyệt
 */
app.use(helmet());

/**
 * CORS (Cross-Origin Resource Sharing):
 * Chỉ cho phép các origin trong whitelist gửi request.
 * Trong production, origin là domain của frontend app.
 */
app.use(cors({
  origin: config.security.CORS_ORIGINS,
  methods: ['GET', 'POST'],         // Chỉ cho phép method cần thiết
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,                  // Cho phép gửi cookie/token
  maxAge: 86400,                      // Cache preflight 24h
}));

/**
 * Body parser với giới hạn kích thước.
 * Giới hạn 10KB — đủ cho payment request, ngăn payload bomb.
 */
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

/**
 * Morgan HTTP request logging.
 * Development: format 'dev' (có màu, ngắn gọn)
 * Production: format 'combined' (chi tiết, chuẩn Apache)
 *
 * Log này phục vụ cho audit trail — theo dõi ai gửi request gì, khi nào.
 */
app.use(morgan(config.isProduction ? 'combined' : 'dev'));

// ---------------------------------------------------------------------------
// GẮN MODELS VÀO APP (để controller truy cập qua req.app.get('models'))
// ---------------------------------------------------------------------------

app.set('models', { Transaction });

// ---------------------------------------------------------------------------
// ROUTES
// ---------------------------------------------------------------------------

/**
 * Health check endpoint.
 * Kubernetes sử dụng endpoint này cho liveness/readiness probe.
 * Kiểm tra cả server và database connection.
 */
app.get('/health', async (_req, res) => {
  try {
    await sequelize.authenticate();
    return res.status(200).json({
      status: 'healthy',
      service: 'payment-service',
      database: 'connected',
      timestamp: new Date().toISOString(),
    });
  } catch {
    return res.status(503).json({
      status: 'unhealthy',
      service: 'payment-service',
      database: 'disconnected',
      timestamp: new Date().toISOString(),
    });
  }
});

/**
 * API Routes cho Payment Service.
 *
 * POST /api/payments      → Tạo giao dịch mới
 * GET  /api/payments       → Liệt kê giao dịch (phân trang, mask dữ liệu)
 * GET  /api/payments/:id   → Xem chi tiết giao dịch (giải mã)
 *
 * Lưu ý: Trong production, các route này nằm sau API Gateway
 * và middleware xác thực JWT. Ở đây chưa thêm auth middleware
 * vì việc verify JWT được thực hiện ở Gateway.
 */
app.post('/api/payments', paymentController.createTransaction);
app.get('/api/payments', paymentController.listTransactions);
app.get('/api/payments/:id', paymentController.getTransaction);

// ---------------------------------------------------------------------------
// XỬ LÝ ROUTE KHÔNG TỒN TẠI (404)
// ---------------------------------------------------------------------------

app.use((_req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint không tồn tại',
  });
});

// ---------------------------------------------------------------------------
// GLOBAL ERROR HANDLER
// ---------------------------------------------------------------------------
// Middleware bắt tất cả lỗi không được xử lý trong route handler.
// KHÔNG trả về stack trace hoặc thông tin nội bộ cho client.
// ---------------------------------------------------------------------------

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('[PaymentService] Unhandled error:', err.message);
  console.error(err.stack);

  res.status(500).json({
    success: false,
    message: 'Lỗi hệ thống. Vui lòng thử lại sau.',
  });
});

// ===========================================================================
// KHỞI ĐỘNG SERVER
// ===========================================================================

const PORT = config.ports.PAYMENT_PORT;

/**
 * Khởi động server:
 *   1. Kết nối và xác thực database
 *   2. Đồng bộ schema (tạo bảng nếu chưa có)
 *   3. Lắng nghe trên port đã cấu hình
 *
 * Trong production, sequelize.sync() nên được thay bằng migration files
 * để kiểm soát schema change tốt hơn.
 */
async function startServer() {
  try {
    // Kiểm tra kết nối database
    await sequelize.authenticate();
    console.log('[PaymentService] ✅ Kết nối PostgreSQL thành công');

    // Đồng bộ schema — { alter: true } trong dev để tự động cập nhật cấu trúc bảng
    // Production NÊN dùng migration thay vì sync
    const syncOptions = config.isProduction
      ? {} // Production: KHÔNG tự động thay đổi schema
      : { alter: true }; // Development: tự động cập nhật

    await sequelize.sync(syncOptions);
    console.log('[PaymentService] ✅ Đồng bộ database schema thành công');

    // Khởi động Express server
    app.listen(PORT, () => {
      console.log(`[PaymentService] 🚀 Server đang chạy tại port ${PORT}`);
      console.log(`[PaymentService] 📋 Health check: http://localhost:${PORT}/health`);
      console.log(`[PaymentService] 🔒 Encryption: AES-256-GCM enabled`);
      console.log(`[PaymentService] 🌍 Môi trường: ${config.NODE_ENV}`);
    });
  } catch (error) {
    console.error('[PaymentService] ❌ Không thể khởi động server:', error.message);
    process.exit(1);
  }
}

// Xử lý tín hiệu shutdown graceful
process.on('SIGTERM', async () => {
  console.log('[PaymentService] 🛑 Nhận SIGTERM — đang shutdown gracefully...');
  await sequelize.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('[PaymentService] 🛑 Nhận SIGINT — đang shutdown gracefully...');
  await sequelize.close();
  process.exit(0);
});

// Chạy server
startServer();

module.exports = app; // Export cho testing
