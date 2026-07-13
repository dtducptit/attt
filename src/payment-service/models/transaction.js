'use strict';

/**
 * @fileoverview Model Sequelize cho bảng transactions (giao dịch thanh toán).
 *
 * Các trường nhạy cảm (số thẻ, CVV, tài khoản) được mã hóa bằng AES-256-GCM
 * TRƯỚC KHI lưu vào database. Cột trong DB chỉ chứa ciphertext (hex string),
 * KHÔNG BAO GIỜ lưu plaintext.
 *
 * === NGUYÊN TẮC BẢO MẬT DỮ LIỆU THẺ (PCI-DSS) ===
 *
 * - PAN (Primary Account Number): mã hóa khi lưu trữ, chỉ hiển thị 4 số cuối
 * - CVV/CVC: KHÔNG ĐƯỢC lưu trữ sau khi xác thực giao dịch (PCI-DSS Requirement 3.2)
 *   → Trong hệ thống này, CVV được mã hóa và lưu tạm cho demo.
 *     Production PHẢI xóa CVV ngay sau khi xử lý thanh toán.
 * - Tài khoản gửi/nhận: mã hóa để bảo vệ thông tin người dùng
 *
 * @module payment-service/models/transaction
 */

const { DataTypes } = require('sequelize');

/**
 * Định nghĩa và khởi tạo model Transaction.
 *
 * @param {import('sequelize').Sequelize} sequelize - Instance Sequelize đã kết nối DB
 * @returns {import('sequelize').Model} Model Transaction
 */
module.exports = (sequelize) => {
  const Transaction = sequelize.define(
    'Transaction',
    {
      // =====================================================================
      // KHÓA CHÍNH — UUID v4
      // =====================================================================
      // Sử dụng UUID thay vì auto-increment integer vì:
      //   1. Không thể đoán được ID tiếp theo → ngăn IDOR attack
      //   2. Unique trên toàn hệ thống phân tán → hỗ trợ microservice
      //   3. Có thể tạo ở client-side mà không cần query DB
      // =====================================================================
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
        allowNull: false,
        comment: 'ID giao dịch — UUID v4, không thể đoán được',
      },

      // =====================================================================
      // TÀI KHOẢN GỬI (đã mã hóa)
      // =====================================================================
      // Lưu dưới dạng ciphertext hex (AES-256-GCM).
      // Chuỗi hex bao gồm: IV (24) + AuthTag (32) + EncryptedData
      // Tổng chiều dài phụ thuộc vào plaintext gốc.
      // =====================================================================
      sender_account: {
        type: DataTypes.STRING(512),
        allowNull: false,
        comment: 'Tài khoản người gửi — đã mã hóa AES-256-GCM (hex)',
        validate: {
          notEmpty: {
            msg: 'Tài khoản người gửi không được để trống',
          },
        },
      },

      // =====================================================================
      // TÀI KHOẢN NHẬN (đã mã hóa)
      // =====================================================================
      receiver_account: {
        type: DataTypes.STRING(512),
        allowNull: false,
        comment: 'Tài khoản người nhận — đã mã hóa AES-256-GCM (hex)',
        validate: {
          notEmpty: {
            msg: 'Tài khoản người nhận không được để trống',
          },
        },
      },

      // =====================================================================
      // SỐ TIỀN GIAO DỊCH
      // =====================================================================
      // Sử dụng DECIMAL(15, 2) thay vì FLOAT để tránh lỗi làm tròn số thập phân.
      // Ví dụ: FLOAT(0.1 + 0.2) = 0.30000000000000004
      //         DECIMAL(0.1 + 0.2) = 0.30 ✓
      // =====================================================================
      amount: {
        type: DataTypes.DECIMAL(15, 2),
        allowNull: false,
        comment: 'Số tiền giao dịch — DECIMAL để tránh lỗi floating point',
        validate: {
          isDecimal: {
            msg: 'Số tiền phải là số thập phân hợp lệ',
          },
          min: {
            args: [0.01],
            msg: 'Số tiền giao dịch phải lớn hơn 0',
          },
        },
      },

      // =====================================================================
      // SỐ THẺ THANH TOÁN (đã mã hóa)
      // =====================================================================
      // Lưu ciphertext hex của PAN (Primary Account Number).
      // Khi hiển thị cho người dùng, chỉ giải mã và hiện 4 số cuối: ****1234
      // =====================================================================
      card_number: {
        type: DataTypes.STRING(512),
        allowNull: false,
        comment: 'Số thẻ — đã mã hóa AES-256-GCM. CHỈ hiển thị 4 số cuối',
        validate: {
          notEmpty: {
            msg: 'Số thẻ không được để trống',
          },
        },
      },

      // =====================================================================
      // CVV (đã mã hóa)
      // =====================================================================
      // ⚠️ CẢNH BÁO PCI-DSS: CVV KHÔNG NÊN lưu trữ lâu dài.
      // Trong production, cột này nên được xóa (SET NULL) sau khi giao dịch
      // được xử lý xong. Ở đây lưu cho mục đích demo.
      // =====================================================================
      cvv: {
        type: DataTypes.STRING(512),
        allowNull: false,
        comment: 'CVV — đã mã hóa. PCI-DSS yêu cầu xóa sau khi xử lý xong',
        validate: {
          notEmpty: {
            msg: 'CVV không được để trống',
          },
        },
      },

      // =====================================================================
      // TRẠNG THÁI GIAO DỊCH
      // =====================================================================
      // Sử dụng ENUM để giới hạn các giá trị hợp lệ:
      //   - pending:   đang chờ xử lý (vừa tạo)
      //   - completed: giao dịch thành công
      //   - failed:    giao dịch thất bại (thiếu số dư, lỗi hệ thống, v.v.)
      // =====================================================================
      status: {
        type: DataTypes.ENUM('pending', 'completed', 'failed'),
        defaultValue: 'pending',
        allowNull: false,
        comment: 'Trạng thái giao dịch: pending | completed | failed',
        validate: {
          isIn: {
            args: [['pending', 'completed', 'failed']],
            msg: 'Trạng thái phải là: pending, completed, hoặc failed',
          },
        },
      },
    },
    {
      // =====================================================================
      // CẤU HÌNH MODEL
      // =====================================================================
      tableName: 'transactions',

      // Tự động thêm cột created_at và updated_at
      timestamps: true,

      // Đổi tên cột timestamp cho đúng convention snake_case của PostgreSQL
      createdAt: 'created_at',
      updatedAt: 'updated_at',

      // Thêm index cho các cột thường xuyên truy vấn
      indexes: [
        {
          name: 'idx_transactions_status',
          fields: ['status'],
          comment: 'Index tìm kiếm theo trạng thái giao dịch',
        },
        {
          name: 'idx_transactions_created_at',
          fields: ['created_at'],
          comment: 'Index sắp xếp theo thời gian tạo',
        },
      ],

      // Tắt paranoid mode (soft delete) — giao dịch không nên xóa mềm
      // vì cần giữ audit trail đầy đủ
      paranoid: false,
    }
  );

  return Transaction;
};
