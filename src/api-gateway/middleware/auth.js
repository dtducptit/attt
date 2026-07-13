'use strict';

const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

// ============================================================================
// JWT Authentication Middleware
// Middleware xác thực JSON Web Token cho API Gateway
// Sử dụng thuật toán RS256 (RSA + SHA-256) để đảm bảo tính toàn vẹn
// và xác thực nguồn gốc của token.
// ============================================================================

/**
 * Đọc khóa công khai RSA để xác minh chữ ký JWT.
 * Khóa công khai được lưu trữ riêng biệt với khóa bí mật (private key)
 * theo nguyên tắc tách biệt quyền hạn (Separation of Duties).
 *
 * @returns {string} Nội dung khóa công khai RSA
 */
const getPublicKey = () => {
  // Đường dẫn khóa công khai - trong production sẽ mount từ Kubernetes Secret
  const publicKeyPath = process.env.JWT_PUBLIC_KEY_PATH
    || path.join(__dirname, '..', 'keys', 'public.pem');

  try {
    return fs.readFileSync(publicKeyPath, 'utf8');
  } catch (error) {
    // Ghi log lỗi nhưng KHÔNG tiết lộ đường dẫn file trong response
    // để tránh lộ thông tin hệ thống (Information Disclosure)
    console.error('[AUTH] Không thể đọc khóa công khai JWT:', error.message);
    throw new Error('Lỗi cấu hình xác thực hệ thống');
  }
};

/**
 * Trích xuất Bearer token từ header Authorization.
 * Tuân theo chuẩn RFC 6750 - Bearer Token Usage.
 *
 * @param {import('express').Request} req - Express request object
 * @returns {string|null} JWT token hoặc null nếu không tìm thấy
 */
const extractBearerToken = (req) => {
  const authHeader = req.headers.authorization;

  // Kiểm tra header Authorization có tồn tại không
  if (!authHeader) {
    return null;
  }

  // Kiểm tra định dạng "Bearer <token>" - phải bắt đầu bằng "Bearer "
  // Sử dụng so sánh chính xác để tránh bypass bằng cách thay đổi chữ hoa/thường
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return null;
  }

  return parts[1];
};

/**
 * Middleware xác thực JWT chính.
 *
 * Quy trình xác thực:
 * 1. Trích xuất token từ header Authorization
 * 2. Xác minh chữ ký số bằng khóa công khai RSA (RS256)
 * 3. Kiểm tra thời hạn (exp), thời điểm phát hành (iat), issuer, audience
 * 4. Gắn thông tin người dùng đã giải mã vào req.user
 *
 * Mã lỗi trả về:
 * - 401 Unauthorized: Không có token hoặc token không hợp lệ
 * - 403 Forbidden: Token hết hạn hoặc quyền không đủ
 *
 * @param {import('express').Request} req - Express request object
 * @param {import('express').Response} res - Express response object
 * @param {import('express').NextFunction} next - Express next middleware
 * @returns {void}
 */
const authenticateJWT = (req, res, next) => {
  // Bước 1: Trích xuất token từ header
  const token = extractBearerToken(req);

  if (!token) {
    // 401 - Không có token: người dùng chưa đăng nhập
    // Trả về header WWW-Authenticate theo chuẩn RFC 6750
    return res.status(401).json({
      success: false,
      error: {
        code: 'AUTHENTICATION_REQUIRED',
        message: 'Yêu cầu xác thực. Vui lòng cung cấp Bearer token trong header Authorization.',
      },
      // Không tiết lộ chi tiết kỹ thuật để tránh Information Disclosure
    });
  }

  try {
    // Bước 2: Lấy khóa công khai để xác minh chữ ký
    const publicKey = getPublicKey();

    // Bước 3: Xác minh và giải mã token
    // Các tùy chọn xác minh nghiêm ngặt:
    const verifyOptions = {
      // Chỉ chấp nhận thuật toán RS256 - chặn algorithm confusion attack
      // Kẻ tấn công có thể cố chuyển sang HS256 để dùng public key làm secret
      algorithms: ['RS256'],

      // Kiểm tra issuer - đảm bảo token được phát hành bởi auth-service
      issuer: process.env.JWT_ISSUER || 'payment-system-auth',

      // Kiểm tra audience - đảm bảo token dành cho hệ thống này
      audience: process.env.JWT_AUDIENCE || 'payment-system-api',

      // Bật kiểm tra thời hạn (mặc định đã bật, khai báo rõ ràng)
      clockTolerance: 30, // Cho phép sai lệch 30 giây giữa các server
    };

    const decoded = jwt.verify(token, publicKey, verifyOptions);

    // Bước 4: Gắn thông tin người dùng vào request
    // Chỉ gắn các trường cần thiết, không gắn toàn bộ payload
    req.user = {
      id: decoded.sub,           // Subject - ID người dùng
      email: decoded.email,       // Email người dùng
      role: decoded.role,         // Vai trò (admin, user, merchant)
      permissions: decoded.permissions || [], // Danh sách quyền
      sessionId: decoded.jti,     // JWT ID - dùng để theo dõi phiên
    };

    // Ghi log xác thực thành công (không ghi token để bảo mật)
    console.info(`[AUTH] Xác thực thành công | User: ${decoded.sub} | Role: ${decoded.role}`);

    next();
  } catch (error) {
    // Xử lý các loại lỗi JWT cụ thể
    if (error instanceof jwt.TokenExpiredError) {
      // 403 - Token hết hạn: người dùng cần đăng nhập lại hoặc refresh token
      console.warn(`[AUTH] Token hết hạn tại: ${error.expiredAt}`);
      return res.status(403).json({
        success: false,
        error: {
          code: 'TOKEN_EXPIRED',
          message: 'Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.',
          // Cung cấp thời điểm hết hạn để client biết cần refresh
          expiredAt: error.expiredAt,
        },
      });
    }

    if (error instanceof jwt.JsonWebTokenError) {
      // 403 - Token không hợp lệ: có thể bị giả mạo hoặc sai định dạng
      // KHÔNG tiết lộ lý do cụ thể để tránh kẻ tấn công khai thác
      console.error(`[AUTH] Token không hợp lệ: ${error.message}`);
      return res.status(403).json({
        success: false,
        error: {
          code: 'INVALID_TOKEN',
          message: 'Token xác thực không hợp lệ.',
        },
      });
    }

    if (error instanceof jwt.NotBeforeError) {
      // 403 - Token chưa có hiệu lực (nbf claim)
      console.warn(`[AUTH] Token chưa có hiệu lực cho đến: ${error.date}`);
      return res.status(403).json({
        success: false,
        error: {
          code: 'TOKEN_NOT_ACTIVE',
          message: 'Token chưa có hiệu lực.',
        },
      });
    }

    // Lỗi không xác định - có thể do cấu hình sai
    console.error('[AUTH] Lỗi xác thực không xác định:', error.message);
    return res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_AUTH_ERROR',
        message: 'Lỗi hệ thống xác thực. Vui lòng thử lại sau.',
      },
    });
  }
};

/**
 * Middleware kiểm tra quyền truy cập dựa trên vai trò (Role-Based Access Control).
 * Sử dụng sau middleware authenticateJWT.
 *
 * Nguyên tắc Least Privilege: Chỉ cho phép truy cập nếu người dùng
 * có đúng vai trò được yêu cầu.
 *
 * @param {...string} allowedRoles - Danh sách vai trò được phép truy cập
 * @returns {import('express').RequestHandler} Express middleware
 *
 * @example
 * // Chỉ admin mới được truy cập
 * router.get('/admin', authenticateJWT, authorizeRoles('admin'), handler);
 *
 * // Admin hoặc merchant đều được
 * router.get('/reports', authenticateJWT, authorizeRoles('admin', 'merchant'), handler);
 */
const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    // Kiểm tra xem middleware auth đã chạy chưa
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'AUTHENTICATION_REQUIRED',
          message: 'Yêu cầu xác thực trước khi kiểm tra quyền.',
        },
      });
    }

    // Kiểm tra vai trò người dùng có nằm trong danh sách cho phép không
    if (!allowedRoles.includes(req.user.role)) {
      // Ghi log cảnh báo - có thể là dấu hiệu tấn công privilege escalation
      console.warn(
        `[AUTH] Truy cập bị từ chối | User: ${req.user.id} | Role: ${req.user.role} | Required: ${allowedRoles.join(', ')}`
      );

      return res.status(403).json({
        success: false,
        error: {
          code: 'INSUFFICIENT_PERMISSIONS',
          message: 'Bạn không có quyền truy cập tài nguyên này.',
        },
      });
    }

    next();
  };
};

module.exports = {
  authenticateJWT,
  authorizeRoles,
  extractBearerToken,
};
