'use strict';

/**
 * @fileoverview Entry point cho Auth Service (Xác thực & Phân quyền).
 *
 * Auth Service chịu trách nhiệm:
 *   1. Đăng ký tài khoản mới (register)
 *   2. Đăng nhập và cấp JWT token (login)
 *   3. Làm mới token (refresh)
 *   4. Xác minh token cho các service nội bộ (verify)
 *
 * Server được bảo vệ bởi:
 *   - Helmet: HTTP security headers
 *   - CORS: giới hạn origin
 *   - Body size limit: ngăn payload bomb
 *   - Morgan: audit log
 *
 * @module auth-service/server
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const { Sequelize } = require('sequelize');

// Cấu hình tập trung
const config = require('../shared/config');

// Controller
const authController = require('./controllers/authController');

// ===========================================================================
// KHỞI TẠO DATABASE (Sequelize + PostgreSQL)
// ===========================================================================

/**
 * Instance Sequelize kết nối đến database Auth.
 * Mỗi service có database riêng (Database-per-Service pattern)
 * để đảm bảo loose coupling giữa các service.
 */
const sequelize = new Sequelize(
  config.database.AUTH_DB,
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

// Khởi tạo model User
const User = require('./models/user')(sequelize);

// ===========================================================================
// KHỞI TẠO EXPRESS APP
// ===========================================================================

const app = express();

// ---------------------------------------------------------------------------
// MIDDLEWARE BẢO MẬT
// ---------------------------------------------------------------------------

/**
 * Helmet: thiết lập các HTTP security headers.
 * Xem chi tiết tại: https://helmetjs.github.io/
 */
app.use(helmet());

/**
 * CORS: Cross-Origin Resource Sharing.
 * Giới hạn domain được phép gọi API.
 */
app.use(cors({
  origin: config.security.CORS_ORIGINS,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400,
}));

/**
 * Body parser với giới hạn kích thước.
 * Auth requests thường nhỏ (username + password) → giới hạn 10KB là đủ.
 */
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

/**
 * Morgan: HTTP request logging cho audit trail.
 */
app.use(morgan(config.isProduction ? 'combined' : 'dev'));

// ---------------------------------------------------------------------------
// GẮN MODELS VÀO APP
// ---------------------------------------------------------------------------
// Controller truy cập model qua req.app.get('models').User
// Cách này giúp controller không phụ thuộc trực tiếp vào Sequelize instance
// → dễ mock khi viết unit test
// ---------------------------------------------------------------------------

app.set('models', { User });

// ---------------------------------------------------------------------------
// ROUTES
// ---------------------------------------------------------------------------

/**
 * Health check endpoint cho Kubernetes liveness/readiness probe.
 * Kiểm tra cả Express server và kết nối database.
 */
app.get('/health', async (_req, res) => {
  try {
    await sequelize.authenticate();
    return res.status(200).json({
      status: 'healthy',
      service: 'auth-service',
      database: 'connected',
      timestamp: new Date().toISOString(),
    });
  } catch {
    return res.status(503).json({
      status: 'unhealthy',
      service: 'auth-service',
      database: 'disconnected',
      timestamp: new Date().toISOString(),
    });
  }
});

/**
 * Auth API Routes.
 *
 * POST /api/auth/register  → Đăng ký tài khoản
 * POST /api/auth/login     → Đăng nhập, nhận JWT
 * POST /api/auth/refresh   → Làm mới access token
 * GET  /api/auth/verify    → Xác minh token (cho internal services)
 */
app.post('/api/auth/register', authController.register);
app.post('/api/auth/login', authController.login);
app.post('/api/auth/refresh', authController.refreshToken);
app.get('/api/auth/verify', authController.verifyToken);

// ---------------------------------------------------------------------------
// 404 HANDLER
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

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('[AuthService] Unhandled error:', err.message);
  console.error(err.stack);

  res.status(500).json({
    success: false,
    message: 'Lỗi hệ thống. Vui lòng thử lại sau.',
  });
});

// ===========================================================================
// KHỞI ĐỘNG SERVER
// ===========================================================================

const PORT = config.ports.AUTH_PORT;

/**
 * Khởi động Auth Service:
 *   1. Kết nối database
 *   2. Đồng bộ schema
 *   3. Kiểm tra JWT keys
 *   4. Lắng nghe HTTP request
 */
async function startServer() {
  try {
    // Kết nối database
    await sequelize.authenticate();
    console.log('[AuthService] ✅ Kết nối PostgreSQL thành công');

    // Đồng bộ schema
    const syncOptions = config.isProduction
      ? {}
      : { alter: true };

    await sequelize.sync(syncOptions);
    console.log('[AuthService] ✅ Đồng bộ database schema thành công');

    // Kiểm tra JWT keys
    if (!config.jwt.PRIVATE_KEY) {
      console.warn('[AuthService] ⚠️  JWT private key chưa được cấu hình!');
      console.warn('[AuthService]    Token signing sẽ thất bại.');
      console.warn('[AuthService]    Tạo key: openssl genrsa -out keys/private.pem 2048');
    }

    if (!config.jwt.PUBLIC_KEY) {
      console.warn('[AuthService] ⚠️  JWT public key chưa được cấu hình!');
      console.warn('[AuthService]    Token verification sẽ thất bại.');
      console.warn('[AuthService]    Tạo key: openssl rsa -in keys/private.pem -pubout -out keys/public.pem');
    }

    // Khởi động Express
    app.listen(PORT, () => {
      console.log(`[AuthService] 🚀 Server đang chạy tại port ${PORT}`);
      console.log(`[AuthService] 📋 Health check: http://localhost:${PORT}/health`);
      console.log(`[AuthService] 🔐 JWT Algorithm: ${config.jwt.ALGORITHM}`);
      console.log(`[AuthService] 🔒 Bcrypt rounds: ${config.security.BCRYPT_SALT_ROUNDS}`);
      console.log(`[AuthService] 🌍 Môi trường: ${config.NODE_ENV}`);
    });
  } catch (error) {
    console.error('[AuthService] ❌ Không thể khởi động server:', error.message);
    process.exit(1);
  }
}

// Graceful shutdown — đóng database connection trước khi thoát
process.on('SIGTERM', async () => {
  console.log('[AuthService] 🛑 Nhận SIGTERM — đang shutdown gracefully...');
  await sequelize.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('[AuthService] 🛑 Nhận SIGINT — đang shutdown gracefully...');
  await sequelize.close();
  process.exit(0);
});

// Chạy server
startServer();

module.exports = app; // Export cho testing
