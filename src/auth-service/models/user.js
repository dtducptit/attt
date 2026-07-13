'use strict';

/**
 * @fileoverview Model Sequelize cho bảng users (người dùng hệ thống).
 *
 * === BẢO MẬT MẬT KHẨU ===
 *
 * Mật khẩu được hash bằng bcrypt trước khi lưu vào database.
 * bcrypt được chọn vì:
 *   1. Thiết kế chuyên biệt cho hashing mật khẩu (không như SHA-256)
 *   2. Tích hợp salt tự động — mỗi hash đều unique
 *   3. Có work factor (salt rounds) — tăng thời gian tính toán
 *      để chống brute-force và rainbow table attack
 *   4. Chống timing attack — so sánh hash bằng hàm constant-time
 *
 * Salt rounds = 12 → mỗi hash mất khoảng 250ms trên CPU hiện đại.
 * Đủ chậm để ngăn brute-force, đủ nhanh để UX chấp nhận được.
 *
 * === PHÂN QUYỀN (RBAC — Role-Based Access Control) ===
 *
 * Hệ thống sử dụng 3 role:
 *   - admin:   quản trị viên — toàn quyền
 *   - user:    người dùng thường — chỉ thao tác trên dữ liệu của mình
 *   - auditor: kiểm toán viên — chỉ đọc (read-only) để audit
 *
 * @module auth-service/models/user
 */

const { DataTypes } = require('sequelize');
const bcrypt = require('bcryptjs');
const config = require('../../shared/config');

/**
 * Định nghĩa và khởi tạo model User.
 *
 * @param {import('sequelize').Sequelize} sequelize - Instance Sequelize đã kết nối DB
 * @returns {import('sequelize').Model} Model User (bao gồm instance method `validatePassword`)
 */
module.exports = (sequelize) => {
  const User = sequelize.define(
    'User',
    {
      // =====================================================================
      // KHÓA CHÍNH — UUID v4
      // =====================================================================
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
        allowNull: false,
        comment: 'ID người dùng — UUID v4',
      },

      // =====================================================================
      // TÊN ĐĂNG NHẬP
      // =====================================================================
      // Unique constraint → mỗi username chỉ thuộc về một user.
      // Đánh index để tăng tốc truy vấn khi đăng nhập.
      // =====================================================================
      username: {
        type: DataTypes.STRING(50),
        allowNull: false,
        unique: {
          name: 'unique_username',
          msg: 'Tên đăng nhập đã tồn tại',
        },
        validate: {
          notEmpty: {
            msg: 'Tên đăng nhập không được để trống',
          },
          len: {
            args: [3, 50],
            msg: 'Tên đăng nhập phải từ 3 đến 50 ký tự',
          },
          // Chỉ cho phép chữ cái, số, gạch dưới, gạch ngang
          // Ngăn injection thông qua username
          is: {
            args: /^[a-zA-Z0-9_-]+$/,
            msg: 'Tên đăng nhập chỉ được chứa chữ cái, số, _ và -',
          },
        },
        comment: 'Tên đăng nhập — unique, 3-50 ký tự, alphanumeric',
      },

      // =====================================================================
      // EMAIL
      // =====================================================================
      email: {
        type: DataTypes.STRING(255),
        allowNull: false,
        unique: {
          name: 'unique_email',
          msg: 'Email đã được sử dụng',
        },
        validate: {
          notEmpty: {
            msg: 'Email không được để trống',
          },
          isEmail: {
            msg: 'Email không hợp lệ',
          },
        },
        comment: 'Địa chỉ email — unique, dùng cho thông báo và khôi phục tài khoản',
        // Lưu email dạng lowercase để tránh trùng lặp (User@mail.com vs user@mail.com)
        set(value) {
          if (value) {
            this.setDataValue('email', value.toLowerCase().trim());
          }
        },
      },

      // =====================================================================
      // MẬT KHẨU (bcrypt hash)
      // =====================================================================
      // Cột này lưu bcrypt hash, KHÔNG phải plaintext.
      // Format bcrypt: $2b$12$salt22chars.hash31chars
      //   - $2b$: version identifier
      //   - 12:   cost factor (salt rounds)
      //   - salt: 22 ký tự base64
      //   - hash: 31 ký tự base64
      // =====================================================================
      password: {
        type: DataTypes.STRING(255),
        allowNull: false,
        validate: {
          notEmpty: {
            msg: 'Mật khẩu không được để trống',
          },
          // Kiểm tra độ dài TỐI THIỂU của plaintext password (trước khi hash)
          // Validation này chạy trên giá trị người dùng nhập, TRƯỚC hook beforeCreate
          len: {
            args: [8, 128],
            msg: 'Mật khẩu phải từ 8 đến 128 ký tự',
          },
        },
        comment: 'Mật khẩu — bcrypt hash, KHÔNG BAO GIỜ lưu plaintext',
      },

      // =====================================================================
      // VAI TRÒ (Role)
      // =====================================================================
      // RBAC (Role-Based Access Control): phân quyền dựa trên vai trò
      //   - admin:   quản lý user, xem tất cả giao dịch, cấu hình hệ thống
      //   - user:    tạo giao dịch, xem giao dịch của mình
      //   - auditor: xem tất cả giao dịch (read-only), không thể tạo/sửa/xóa
      // =====================================================================
      role: {
        type: DataTypes.ENUM('admin', 'user', 'auditor'),
        defaultValue: 'user',
        allowNull: false,
        comment: 'Vai trò: admin | user | auditor (RBAC)',
        validate: {
          isIn: {
            args: [['admin', 'user', 'auditor']],
            msg: 'Vai trò phải là: admin, user, hoặc auditor',
          },
        },
      },
    },
    {
      // =====================================================================
      // CẤU HÌNH MODEL
      // =====================================================================
      tableName: 'users',
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at',

      // Index cho các cột thường truy vấn
      indexes: [
        {
          name: 'idx_users_username',
          unique: true,
          fields: ['username'],
        },
        {
          name: 'idx_users_email',
          unique: true,
          fields: ['email'],
        },
        {
          name: 'idx_users_role',
          fields: ['role'],
        },
      ],

      // =====================================================================
      // HOOKS — Tự động hash mật khẩu trước khi lưu
      // =====================================================================
      hooks: {
        /**
         * Hook beforeCreate: hash mật khẩu trước khi INSERT vào database.
         *
         * Quy trình:
         *   1. genSalt(): tạo salt ngẫu nhiên với cost factor từ config
         *   2. hash(): hash password + salt → bcrypt hash string
         *   3. Gán hash vào user.password (ghi đè plaintext)
         *
         * @param {Object} user - Instance User sắp được tạo
         */
        beforeCreate: async (user) => {
          if (user.password) {
            const salt = await bcrypt.genSalt(config.security.BCRYPT_SALT_ROUNDS);
            user.password = await bcrypt.hash(user.password, salt);
          }
        },

        /**
         * Hook beforeUpdate: hash lại mật khẩu nếu bị thay đổi.
         *
         * Chỉ hash khi trường password thực sự thay đổi (changed()),
         * tránh hash lại hash đã có khi update các trường khác.
         *
         * @param {Object} user - Instance User sắp được update
         */
        beforeUpdate: async (user) => {
          if (user.changed('password')) {
            const salt = await bcrypt.genSalt(config.security.BCRYPT_SALT_ROUNDS);
            user.password = await bcrypt.hash(user.password, salt);
          }
        },
      },

      // Ẩn password khỏi JSON output mặc định
      // Khi gọi user.toJSON() hoặc JSON.stringify(user), password bị loại bỏ
      defaultScope: {
        attributes: { exclude: ['password'] },
      },

      // Scope 'withPassword': dùng khi cần verify password (login)
      scopes: {
        withPassword: {
          attributes: { include: ['password'] },
        },
      },
    }
  );

  // =========================================================================
  // INSTANCE METHODS
  // =========================================================================

  /**
   * So sánh plaintext password với bcrypt hash đã lưu trong database.
   *
   * bcrypt.compare() sử dụng constant-time comparison để chống timing attack:
   * thời gian so sánh KHÔNG thay đổi dù password đúng hay sai.
   *
   * @param {string} candidatePassword - Mật khẩu plaintext cần kiểm tra
   * @returns {Promise<boolean>} true nếu password khớp
   */
  User.prototype.validatePassword = async function (candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
  };

  return User;
};
