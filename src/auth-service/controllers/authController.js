'use strict';

/**
 * @fileoverview Controller xác thực và phân quyền người dùng.
 *
 * === CƠ CHẾ XÁC THỰC ===
 *
 * Hệ thống sử dụng JWT (JSON Web Token) với thuật toán RS256:
 *   - RS256 = RSA Signature with SHA-256
 *   - Sử dụng cặp khóa bất đối xứng (asymmetric key pair):
 *       • Private key: chỉ Auth Service giữ → dùng để KÝ token
 *       • Public key: các service khác giữ → dùng để XÁC MINH token
 *   - Ưu điểm so với HS256 (symmetric):
 *       • Các service verify token mà KHÔNG cần biết private key
 *       • Nếu một service bị compromise, attacker không thể tạo token giả
 *       • Phù hợp kiến trúc Zero Trust trong microservice
 *
 * === LUỒNG XÁC THỰC ===
 *
 * 1. Client gửi POST /api/auth/login với username + password
 * 2. Server verify password bằng bcrypt.compare()
 * 3. Nếu đúng → ký JWT bằng private key → trả về access token
 * 4. Client gửi token trong header Authorization: Bearer <token>
 * 5. Gateway/Service verify token bằng public key
 * 6. Token hết hạn → client gọi POST /api/auth/refresh để lấy token mới
 *
 * @module auth-service/controllers/authController
 */

const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const config = require('../../shared/config');

// ===========================================================================
// HÀM TIỆN ÍCH NỘI BỘ
// ===========================================================================

/**
 * Tạo JWT access token với RS256.
 *
 * Payload chứa thông tin tối thiểu cần thiết:
 *   - userId:   để xác định user
 *   - username: để hiển thị (KHÔNG dùng để xác thực)
 *   - role:     để phân quyền (RBAC)
 *
 * KHÔNG đưa thông tin nhạy cảm (email, password hash) vào payload
 * vì JWT payload chỉ được encode (Base64), KHÔNG được mã hóa.
 * Bất kỳ ai có token đều đọc được payload.
 *
 * @param {Object} user - Thông tin user
 * @param {string} user.id - UUID của user
 * @param {string} user.username - Tên đăng nhập
 * @param {string} user.role - Vai trò (admin/user/auditor)
 * @returns {string} JWT token đã ký
 * @throws {Error} Nếu private key chưa được cấu hình
 */
function generateAccessToken(user) {
  if (!config.jwt.PRIVATE_KEY) {
    throw new Error('JWT private key chưa được cấu hình. Kiểm tra keys/private.pem hoặc env JWT_PRIVATE_KEY');
  }

  const payload = {
    userId: user.id,
    username: user.username,
    role: user.role,
    // jti (JWT ID): ID duy nhất cho token → hỗ trợ revocation
    jti: uuidv4(),
    // type: phân biệt access token vs refresh token
    type: 'access',
  };

  return jwt.sign(payload, config.jwt.PRIVATE_KEY, {
    algorithm: config.jwt.ALGORITHM,
    expiresIn: config.jwt.ACCESS_TOKEN_EXPIRY,
    issuer: config.jwt.ISSUER,
    audience: config.jwt.AUDIENCE,
  });
}

/**
 * Tạo refresh token.
 *
 * Refresh token có thời gian sống dài hơn access token (7 ngày vs 1 giờ).
 * Khi access token hết hạn, client dùng refresh token để lấy access token mới
 * mà không cần nhập lại username/password.
 *
 * Trong production, refresh token nên:
 *   - Được lưu trong database (để có thể revoke)
 *   - Sử dụng rotation (mỗi lần refresh → tạo refresh token mới)
 *   - Kiểm tra IP/User-Agent để phát hiện token theft
 *
 * @param {Object} user - Thông tin user
 * @returns {string} JWT refresh token
 */
function generateRefreshToken(user) {
  if (!config.jwt.PRIVATE_KEY) {
    throw new Error('JWT private key chưa được cấu hình');
  }

  const payload = {
    userId: user.id,
    username: user.username,
    role: user.role,
    jti: uuidv4(),
    type: 'refresh',
  };

  return jwt.sign(payload, config.jwt.PRIVATE_KEY, {
    algorithm: config.jwt.ALGORITHM,
    expiresIn: config.jwt.REFRESH_TOKEN_EXPIRY,
    issuer: config.jwt.ISSUER,
    audience: config.jwt.AUDIENCE,
  });
}

/**
 * Validate email format.
 *
 * @param {string} email - Email cần kiểm tra
 * @returns {boolean} true nếu email hợp lệ
 */
function isValidEmail(email) {
  // RFC 5322 simplified regex — đủ tốt cho validation cơ bản
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// ===========================================================================
// CONTROLLER METHODS
// ===========================================================================

/**
 * Đăng ký tài khoản mới.
 *
 * Quy trình:
 *   1. Validate đầu vào (username, email, password)
 *   2. Kiểm tra username/email đã tồn tại chưa
 *   3. Hash password bằng bcrypt (tự động qua Sequelize hook)
 *   4. Tạo user trong database
 *   5. Trả về thông tin user (KHÔNG bao gồm password)
 *
 * @param {import('express').Request} req - Express request
 * @param {string} req.body.username - Tên đăng nhập (3-50 ký tự, alphanumeric)
 * @param {string} req.body.email - Email hợp lệ
 * @param {string} req.body.password - Mật khẩu (8-128 ký tự)
 * @param {string} [req.body.role='user'] - Vai trò (chỉ admin mới được tạo role khác)
 * @param {import('express').Response} res - Express response
 * @returns {Promise<void>}
 */
async function register(req, res) {
  try {
    const { username, email, password, role } = req.body;

    // =======================================================================
    // VALIDATE ĐẦU VÀO
    // =======================================================================
    // Kiểm tra phía server LUÔN LUÔN cần thiết, dù client đã validate.
    // Client-side validation chỉ cải thiện UX, KHÔNG thể tin cậy về bảo mật.
    // =======================================================================

    const errors = [];

    // Validate username
    if (!username || typeof username !== 'string' || !username.trim()) {
      errors.push('Tên đăng nhập (username) là bắt buộc');
    } else if (username.trim().length < 3 || username.trim().length > 50) {
      errors.push('Tên đăng nhập phải từ 3 đến 50 ký tự');
    } else if (!/^[a-zA-Z0-9_-]+$/.test(username.trim())) {
      errors.push('Tên đăng nhập chỉ được chứa chữ cái, số, _ và -');
    }

    // Validate email
    if (!email || typeof email !== 'string' || !email.trim()) {
      errors.push('Email là bắt buộc');
    } else if (!isValidEmail(email.trim())) {
      errors.push('Email không hợp lệ');
    }

    // Validate password
    // Yêu cầu tối thiểu: 8 ký tự
    // Trong production nên yêu cầu: chữ hoa, chữ thường, số, ký tự đặc biệt
    if (!password || typeof password !== 'string') {
      errors.push('Mật khẩu (password) là bắt buộc');
    } else if (password.length < 8 || password.length > 128) {
      errors.push('Mật khẩu phải từ 8 đến 128 ký tự');
    }

    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Dữ liệu đăng ký không hợp lệ',
        errors,
      });
    }

    // =======================================================================
    // KIỂM TRA TRÙNG LẶP
    // =======================================================================
    // Kiểm tra riêng username và email để trả thông báo rõ ràng cho user.
    //
    // ⚠️ LƯU Ý BẢO MẬT: Việc thông báo "username đã tồn tại" có thể giúp
    // attacker enumeration (biết được username nào có trong hệ thống).
    // Trong hệ thống yêu cầu bảo mật cao, nên trả thông báo chung:
    // "Không thể tạo tài khoản với thông tin đã cung cấp"
    // =======================================================================

    const User = req.app.get('models').User;

    const existingUser = await User.unscoped().findOne({
      where: { username: username.trim() },
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Tên đăng nhập đã tồn tại',
      });
    }

    const existingEmail = await User.unscoped().findOne({
      where: { email: email.trim().toLowerCase() },
    });

    if (existingEmail) {
      return res.status(400).json({
        success: false,
        message: 'Email đã được sử dụng',
      });
    }

    // =======================================================================
    // TẠO USER
    // =======================================================================
    // Password được tự động hash bởi Sequelize hook beforeCreate.
    // Role mặc định là 'user' — KHÔNG cho phép tự đăng ký admin/auditor
    // trừ khi request đến từ admin đã xác thực (kiểm tra bổ sung ở đây).
    // =======================================================================

    // Chỉ cho phép role 'user' khi tự đăng ký
    // Admin và auditor phải được tạo bởi admin thông qua API riêng
    const allowedSelfRegisterRoles = ['user'];
    const assignedRole = (role && allowedSelfRegisterRoles.includes(role))
      ? role
      : 'user';

    const newUser = await User.create({
      id: uuidv4(),
      username: username.trim(),
      email: email.trim().toLowerCase(),
      password, // plaintext — sẽ được hash trong hook beforeCreate
      role: assignedRole,
    });

    // =======================================================================
    // RESPONSE
    // =======================================================================
    // KHÔNG trả về password (dù đã hash) trong response.
    // defaultScope đã loại bỏ password, nhưng ta tự tạo object an toàn.
    // =======================================================================

    return res.status(201).json({
      success: true,
      message: 'Đăng ký tài khoản thành công',
      data: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
        created_at: newUser.created_at,
      },
    });
  } catch (error) {
    console.error('[AuthController] register error:', error.message);

    // Xử lý lỗi unique constraint từ database
    if (error.name === 'SequelizeUniqueConstraintError') {
      return res.status(400).json({
        success: false,
        message: 'Tên đăng nhập hoặc email đã tồn tại',
      });
    }

    // Xử lý lỗi validation từ Sequelize
    if (error.name === 'SequelizeValidationError') {
      const messages = error.errors.map((e) => e.message);
      return res.status(400).json({
        success: false,
        message: 'Dữ liệu không hợp lệ',
        errors: messages,
      });
    }

    return res.status(500).json({
      success: false,
      message: 'Lỗi hệ thống khi đăng ký. Vui lòng thử lại sau.',
    });
  }
}

/**
 * Đăng nhập và nhận JWT token.
 *
 * Quy trình:
 *   1. Validate đầu vào (username, password)
 *   2. Tìm user theo username (bao gồm password hash)
 *   3. So sánh password bằng bcrypt.compare() (constant-time)
 *   4. Nếu đúng → tạo access token + refresh token bằng RS256
 *   5. Trả về tokens cho client
 *
 * === CHỐNG BRUTE-FORCE ===
 * Thông báo lỗi KHÔNG phân biệt "username không tồn tại" vs "sai mật khẩu"
 * để ngăn attacker enumeration username hợp lệ.
 * Rate limiting được thực hiện ở API Gateway.
 *
 * @param {import('express').Request} req - Express request
 * @param {string} req.body.username - Tên đăng nhập
 * @param {string} req.body.password - Mật khẩu plaintext
 * @param {import('express').Response} res - Express response
 * @returns {Promise<void>}
 */
async function login(req, res) {
  try {
    const { username, password } = req.body;

    // Validate đầu vào
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Tên đăng nhập và mật khẩu là bắt buộc',
      });
    }

    // =======================================================================
    // TÌM USER VỚI PASSWORD
    // =======================================================================
    // Sử dụng scope 'withPassword' để lấy cả trường password (hash).
    // defaultScope loại bỏ password → cần scope đặc biệt khi verify.
    // =======================================================================

    const User = req.app.get('models').User;

    const user = await User.scope('withPassword').findOne({
      where: { username: username.trim() },
    });

    // =======================================================================
    // THÔNG BÁO LỖI CHUNG (Generic Error Message)
    // =======================================================================
    // QUAN TRỌNG: Dù username sai hay password sai, đều trả cùng thông báo.
    // Nếu trả "username không tồn tại" → attacker biết username nào có.
    // Nếu trả "sai mật khẩu" → attacker biết username hợp lệ và brute-force.
    //
    // Thông báo chung: "Tên đăng nhập hoặc mật khẩu không đúng"
    // =======================================================================

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Tên đăng nhập hoặc mật khẩu không đúng',
      });
    }

    // So sánh password bằng bcrypt
    // bcrypt.compare() là constant-time → không bị timing attack
    const isPasswordValid = await user.validatePassword(password);

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Tên đăng nhập hoặc mật khẩu không đúng',
      });
    }

    // =======================================================================
    // TẠO JWT TOKENS
    // =======================================================================
    // Access token: ngắn hạn (1h), dùng cho mọi API request
    // Refresh token: dài hạn (7d), chỉ dùng để lấy access token mới
    // =======================================================================

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    return res.status(200).json({
      success: true,
      message: 'Đăng nhập thành công',
      data: {
        accessToken,
        refreshToken,
        tokenType: 'Bearer',
        expiresIn: config.jwt.ACCESS_TOKEN_EXPIRY,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
        },
      },
    });
  } catch (error) {
    console.error('[AuthController] login error:', error.message);

    return res.status(500).json({
      success: false,
      message: 'Lỗi hệ thống khi đăng nhập. Vui lòng thử lại sau.',
    });
  }
}

/**
 * Làm mới access token bằng refresh token.
 *
 * Quy trình:
 *   1. Client gửi refresh token trong request body
 *   2. Verify refresh token bằng public key
 *   3. Kiểm tra token type = 'refresh'
 *   4. Tạo access token mới
 *   5. (Tùy chọn) Tạo refresh token mới (rotation)
 *
 * === TOKEN ROTATION ===
 * Mỗi lần refresh, ta tạo refresh token mới và vô hiệu hóa token cũ.
 * Nếu attacker đánh cắp refresh token cũ và cố dùng → phát hiện được
 * vì token đã bị thay thế → có thể revoke tất cả token của user.
 *
 * @param {import('express').Request} req - Express request
 * @param {string} req.body.refreshToken - Refresh token hiện tại
 * @param {import('express').Response} res - Express response
 * @returns {Promise<void>}
 */
async function refreshToken(req, res) {
  try {
    const { refreshToken: token } = req.body;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token là bắt buộc',
      });
    }

    // =======================================================================
    // VERIFY REFRESH TOKEN
    // =======================================================================
    // Sử dụng public key để verify chữ ký RS256.
    // jwt.verify() kiểm tra:
    //   1. Chữ ký hợp lệ (không bị giả mạo)
    //   2. Token chưa hết hạn (exp claim)
    //   3. Issuer và audience khớp với cấu hình
    // =======================================================================

    if (!config.jwt.PUBLIC_KEY) {
      throw new Error('JWT public key chưa được cấu hình');
    }

    let decoded;
    try {
      decoded = jwt.verify(token, config.jwt.PUBLIC_KEY, {
        algorithms: [config.jwt.ALGORITHM],
        issuer: config.jwt.ISSUER,
        audience: config.jwt.AUDIENCE,
      });
    } catch (jwtError) {
      // Phân loại lỗi JWT để trả HTTP status code phù hợp
      if (jwtError.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          message: 'Refresh token đã hết hạn. Vui lòng đăng nhập lại.',
        });
      }
      return res.status(401).json({
        success: false,
        message: 'Refresh token không hợp lệ',
      });
    }

    // Kiểm tra đây có phải refresh token không (không phải access token)
    if (decoded.type !== 'refresh') {
      return res.status(403).json({
        success: false,
        message: 'Token không phải loại refresh token',
      });
    }

    // =======================================================================
    // KIỂM TRA USER CÒN TỒN TẠI VÀ ACTIVE KHÔNG
    // =======================================================================
    // Trường hợp: user bị xóa/khóa SAU KHI token được cấp
    // → token vẫn hợp lệ về mặt chữ ký nhưng user không còn quyền truy cập
    // =======================================================================

    const User = req.app.get('models').User;
    const user = await User.findByPk(decoded.userId);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Tài khoản không tồn tại hoặc đã bị vô hiệu hóa',
      });
    }

    // Tạo access token mới
    const newAccessToken = generateAccessToken(user);

    // Token rotation: tạo refresh token mới (tùy chọn)
    const newRefreshToken = generateRefreshToken(user);

    return res.status(200).json({
      success: true,
      message: 'Token đã được làm mới',
      data: {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        tokenType: 'Bearer',
        expiresIn: config.jwt.ACCESS_TOKEN_EXPIRY,
      },
    });
  } catch (error) {
    console.error('[AuthController] refreshToken error:', error.message);

    return res.status(500).json({
      success: false,
      message: 'Lỗi hệ thống khi làm mới token. Vui lòng thử lại sau.',
    });
  }
}

/**
 * Xác minh JWT token — endpoint dành cho các service nội bộ.
 *
 * Khi Gateway hoặc service khác nhận được request từ client,
 * chúng gọi endpoint này để verify token thay vì tự verify.
 * (Hoặc tự verify bằng public key — tùy kiến trúc.)
 *
 * Endpoint này chỉ nên được truy cập từ internal network (trong Kubernetes).
 * KHÔNG expose ra public internet.
 *
 * @param {import('express').Request} req - Express request
 * @param {string} req.headers.authorization - Header "Bearer <token>"
 * @param {import('express').Response} res - Express response
 * @returns {Promise<void>}
 */
async function verifyToken(req, res) {
  try {
    // =======================================================================
    // TRÍCH XUẤT TOKEN TỪ HEADER
    // =======================================================================
    // Format: Authorization: Bearer eyJhbGciOiJS...
    // Tách "Bearer" và lấy phần token phía sau
    // =======================================================================

    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Token không được cung cấp. Gửi trong header: Authorization: Bearer <token>',
      });
    }

    const token = authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Token rỗng',
      });
    }

    // =======================================================================
    // VERIFY TOKEN
    // =======================================================================

    if (!config.jwt.PUBLIC_KEY) {
      throw new Error('JWT public key chưa được cấu hình');
    }

    let decoded;
    try {
      decoded = jwt.verify(token, config.jwt.PUBLIC_KEY, {
        algorithms: [config.jwt.ALGORITHM],
        issuer: config.jwt.ISSUER,
        audience: config.jwt.AUDIENCE,
      });
    } catch (jwtError) {
      if (jwtError.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          message: 'Token đã hết hạn',
          expired: true,
        });
      }
      if (jwtError.name === 'JsonWebTokenError') {
        return res.status(401).json({
          success: false,
          message: 'Token không hợp lệ',
        });
      }
      return res.status(401).json({
        success: false,
        message: 'Không thể xác minh token',
      });
    }

    // Chỉ chấp nhận access token (không phải refresh token)
    if (decoded.type !== 'access') {
      return res.status(403).json({
        success: false,
        message: 'Loại token không hợp lệ cho API access',
      });
    }

    // Token hợp lệ → trả về thông tin user từ payload
    return res.status(200).json({
      success: true,
      message: 'Token hợp lệ',
      data: {
        userId: decoded.userId,
        username: decoded.username,
        role: decoded.role,
        issuedAt: new Date(decoded.iat * 1000).toISOString(),
        expiresAt: new Date(decoded.exp * 1000).toISOString(),
      },
    });
  } catch (error) {
    console.error('[AuthController] verifyToken error:', error.message);

    return res.status(500).json({
      success: false,
      message: 'Lỗi hệ thống khi xác minh token',
    });
  }
}

// ===========================================================================
// EXPORT
// ===========================================================================

module.exports = {
  register,
  login,
  refreshToken,
  verifyToken,
};
