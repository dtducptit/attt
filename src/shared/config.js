'use strict';

/**
 * @fileoverview Cấu hình tập trung cho toàn bộ hệ thống Microservice Payment.
 * 
 * Tất cả các service (Gateway, Auth, Payment) đều đọc cấu hình từ file này.
 * Trong môi trường production, các giá trị nhạy cảm (secret key, database password)
 * PHẢI được cung cấp qua biến môi trường (environment variables), KHÔNG hardcode.
 *
 * @module shared/config
 */

require('dotenv').config();
const path = require('path');
const fs = require('fs');

// ---------------------------------------------------------------------------
// Hàm tiện ích: đọc file key RSA (dùng cho JWT RS256)
// Nếu file không tồn tại, trả về null — service sẽ báo lỗi khi khởi động
// ---------------------------------------------------------------------------

/**
 * Đọc nội dung file key từ đường dẫn tương đối so với thư mục gốc project.
 * @param {string} relativePath - Đường dẫn tương đối đến file key
 * @returns {Buffer|null} Nội dung file hoặc null nếu không tìm thấy
 */
function readKeyFile(relativePath) {
  try {
    const fullPath = path.resolve(__dirname, '..', '..', relativePath);
    return fs.readFileSync(fullPath);
  } catch {
    // Trong development có thể chưa tạo key pair — trả về null
    return null;
  }
}

// ===========================================================================
// CẤU HÌNH CỔNG (PORT) CHO TỪNG SERVICE
// ===========================================================================

/** @type {Object} Cấu hình port cho các service */
const ports = {
  /** API Gateway — điểm vào duy nhất cho client */
  GATEWAY_PORT: parseInt(process.env.GATEWAY_PORT, 10) || 3000,

  /** Auth Service — xác thực & phân quyền */
  AUTH_PORT: parseInt(process.env.AUTH_PORT, 10) || 3001,

  /** Payment Service — xử lý giao dịch thanh toán */
  PAYMENT_PORT: parseInt(process.env.PAYMENT_PORT, 10) || 3002,
};

// ===========================================================================
// CẤU HÌNH JWT (JSON Web Token) — Thuật toán RS256
// ===========================================================================
// RS256 sử dụng cặp khóa bất đối xứng (asymmetric key pair):
//   - Private key: chỉ Auth Service giữ, dùng để KÝ (sign) token
//   - Public key: các service khác dùng để XÁC MINH (verify) token
// Lợi ích: các service không cần biết private key → giảm rủi ro lộ secret
// ===========================================================================

/** @type {Object} Cấu hình JWT RS256 */
const jwt = {
  /** Thuật toán ký — RS256 (RSA Signature with SHA-256) */
  ALGORITHM: 'RS256',

  /**
   * Private key RSA — chỉ Auth Service được phép sử dụng.
   * Ưu tiên đọc từ biến môi trường, fallback sang file.
   */
  PRIVATE_KEY: process.env.JWT_PRIVATE_KEY || readKeyFile('keys/private.pem'),

  /**
   * Public key RSA — dùng để verify token ở Gateway và các service khác.
   * Ưu tiên đọc từ biến môi trường, fallback sang file.
   */
  PUBLIC_KEY: process.env.JWT_PUBLIC_KEY || readKeyFile('keys/public.pem'),

  /** Thời gian sống của access token (1 giờ) */
  ACCESS_TOKEN_EXPIRY: process.env.JWT_ACCESS_EXPIRY || '1h',

  /** Thời gian sống của refresh token (7 ngày) */
  REFRESH_TOKEN_EXPIRY: process.env.JWT_REFRESH_EXPIRY || '7d',

  /** Issuer — định danh hệ thống phát hành token */
  ISSUER: process.env.JWT_ISSUER || 'payment-system-auth',

  /** Audience — đối tượng sử dụng token */
  AUDIENCE: process.env.JWT_AUDIENCE || 'payment-system-services',
};

// ===========================================================================
// CẤU HÌNH CƠ SỞ DỮ LIỆU (PostgreSQL)
// ===========================================================================
// Mỗi service nên có database riêng (Database-per-Service pattern)
// để đảm bảo tính độc lập và giảm coupling giữa các service.
// ===========================================================================

/** @type {Object} Cấu hình database PostgreSQL */
const database = {
  /** Host của PostgreSQL server */
  HOST: process.env.DB_HOST || 'localhost',

  /** Port của PostgreSQL (mặc định 5432) */
  PORT: parseInt(process.env.DB_PORT, 10) || 5432,

  /** Database cho Auth Service */
  AUTH_DB: process.env.AUTH_DB_NAME || 'auth_service_db',

  /** Database cho Payment Service */
  PAYMENT_DB: process.env.PAYMENT_DB_NAME || 'payment_service_db',

  /** Tên đăng nhập database */
  USERNAME: process.env.DB_USERNAME || 'postgres',

  /** Mật khẩu database — BẮT BUỘC đặt qua env var trong production */
  PASSWORD: process.env.DB_PASSWORD || 'postgres',

  /** Dialect — loại database sử dụng */
  DIALECT: 'postgres',

  /** Cấu hình connection pool */
  POOL: {
    /** Số kết nối tối đa trong pool */
    MAX: parseInt(process.env.DB_POOL_MAX, 10) || 10,
    /** Số kết nối tối thiểu duy trì */
    MIN: parseInt(process.env.DB_POOL_MIN, 10) || 2,
    /** Thời gian chờ kết nối (ms) */
    ACQUIRE: parseInt(process.env.DB_POOL_ACQUIRE, 10) || 30000,
    /** Thời gian idle trước khi đóng kết nối (ms) */
    IDLE: parseInt(process.env.DB_POOL_IDLE, 10) || 10000,
  },

  /** Cấu hình SSL cho kết nối database trong production */
  SSL: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,

  /** Tắt log SQL trong production để tránh lộ dữ liệu nhạy cảm */
  LOGGING: process.env.NODE_ENV === 'production' ? false : console.log,
};

// ===========================================================================
// CẤU HÌNH MÃ HÓA (Encryption) — AES-256-GCM
// ===========================================================================
// AES-256-GCM (Galois/Counter Mode) được chọn vì:
//   1. Authenticated Encryption: vừa mã hóa vừa xác thực tính toàn vẹn
//   2. 256-bit key: độ dài khóa đủ mạnh cho dữ liệu tài chính
//   3. GCM mode: hiệu suất cao, hỗ trợ xử lý song song
//   4. Auth Tag: phát hiện nếu ciphertext bị tampering (giả mạo)
//
// QUAN TRỌNG: Encryption key PHẢI được quản lý bởi KMS (Key Management System)
// trong production. KHÔNG BAO GIỜ hardcode key trong source code.
// ===========================================================================

/** @type {Object} Cấu hình mã hóa AES-256-GCM */
const encryption = {
  /** Thuật toán mã hóa */
  ALGORITHM: 'aes-256-gcm',

  /**
   * Khóa mã hóa 256-bit (32 bytes) — dạng hex string (64 ký tự hex).
   * Trong production, key này PHẢI được lấy từ AWS KMS, HashiCorp Vault,
   * hoặc hệ thống quản lý khóa tương đương.
   */
  KEY: process.env.ENCRYPTION_KEY
    || 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',

  /**
   * Độ dài IV (Initialization Vector) — 12 bytes (96 bits).
   * GCM yêu cầu IV 96-bit để đạt hiệu suất tối ưu.
   * IV PHẢI là duy nhất cho mỗi lần mã hóa với cùng một key.
   */
  IV_LENGTH: 12,

  /**
   * Độ dài Auth Tag — 16 bytes (128 bits).
   * Auth Tag dùng để xác minh tính toàn vẹn của dữ liệu sau khi giải mã.
   */
  AUTH_TAG_LENGTH: 16,
};

// ===========================================================================
// CẤU HÌNH URL CÁC SERVICE (Inter-Service Communication)
// ===========================================================================
// Trong Kubernetes, các service giao tiếp qua Service DNS name.
// Trong development, sử dụng localhost với port tương ứng.
// ===========================================================================

/** @type {Object} URL các service nội bộ */
const services = {
  /** URL của API Gateway */
  GATEWAY_URL: process.env.GATEWAY_URL
    || `http://localhost:${ports.GATEWAY_PORT}`,

  /** URL của Auth Service */
  AUTH_URL: process.env.AUTH_URL
    || `http://localhost:${ports.AUTH_PORT}`,

  /** URL của Payment Service */
  PAYMENT_URL: process.env.PAYMENT_URL
    || `http://localhost:${ports.PAYMENT_PORT}`,
};

// ===========================================================================
// CẤU HÌNH BẢO MẬT CHUNG
// ===========================================================================

/** @type {Object} Các cấu hình bảo mật bổ sung */
const security = {
  /** Số vòng hash bcrypt — càng cao càng an toàn nhưng chậm hơn */
  BCRYPT_SALT_ROUNDS: parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12,

  /** Giới hạn rate limit (số request / phút) */
  RATE_LIMIT_WINDOW_MS: 60 * 1000,
  RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX, 10) || 100,

  /** Danh sách origin được phép CORS */
  CORS_ORIGINS: process.env.CORS_ORIGINS
    ? process.env.CORS_ORIGINS.split(',')
    : ['http://localhost:3000'],
};

// ===========================================================================
// EXPORT MODULE
// ===========================================================================

module.exports = {
  ports,
  jwt,
  database,
  encryption,
  services,
  security,

  /** Môi trường hiện tại */
  NODE_ENV: process.env.NODE_ENV || 'development',

  /** Kiểm tra có phải môi trường production không */
  isProduction: process.env.NODE_ENV === 'production',
};
