'use strict';

/**
 * @fileoverview Controller xử lý các API endpoint liên quan đến giao dịch thanh toán.
 *
 * === NGUYÊN TẮC BẢO MẬT CHÍNH ===
 *
 * 1. MÃ HÓA TRƯỚC KHI LƯU (Encrypt-then-Store):
 *    Tất cả dữ liệu nhạy cảm (số thẻ, CVV, tài khoản) được mã hóa bằng
 *    AES-256-GCM TRƯỚC KHI ghi vào database. Database chỉ chứa ciphertext.
 *
 * 2. GIẢI MÃ KHI CẦN (Decrypt-on-Read):
 *    Chỉ giải mã khi có request hợp lệ từ user được xác thực.
 *    Dữ liệu plaintext KHÔNG được cache hoặc log.
 *
 * 3. MASKING (Che giấu):
 *    Khi liệt kê danh sách giao dịch, số thẻ được mask: ****1234
 *    Chỉ hiển thị đầy đủ khi xem chi tiết từng giao dịch.
 *
 * 4. ERROR HANDLING AN TOÀN:
 *    Lỗi nội bộ (stack trace, SQL error) KHÔNG được trả về client.
 *    Chỉ trả về thông báo chung để tránh Information Disclosure.
 *
 * @module payment-service/controllers/paymentController
 */

const { v4: uuidv4 } = require('uuid');
const { encryptToHex, decryptFromHex } = require('../encryption/aes256gcm');
const config = require('../../shared/config');

// Lấy encryption key từ cấu hình tập trung
const ENCRYPTION_KEY = config.encryption.KEY;

/**
 * Tạo giao dịch thanh toán mới.
 *
 * Quy trình:
 *   1. Validate dữ liệu đầu vào (sender, receiver, amount, card, cvv)
 *   2. Mã hóa các trường nhạy cảm bằng AES-256-GCM
 *   3. Lưu bản ghi vào database (chỉ chứa ciphertext)
 *   4. Trả về response với thông tin giao dịch (đã mask số thẻ)
 *
 * @param {import('express').Request} req - Express request object
 * @param {string} req.body.sender_account - Tài khoản người gửi (plaintext)
 * @param {string} req.body.receiver_account - Tài khoản người nhận (plaintext)
 * @param {number} req.body.amount - Số tiền giao dịch
 * @param {string} req.body.card_number - Số thẻ thanh toán (plaintext, 13-19 chữ số)
 * @param {string} req.body.cvv - Mã CVV (plaintext, 3-4 chữ số)
 * @param {import('express').Response} res - Express response object
 * @returns {Promise<void>}
 */
async function createTransaction(req, res) {
  try {
    const { sender_account, receiver_account, amount, card_number, cvv } = req.body;

    // =======================================================================
    // BƯỚC 1: VALIDATE DỮ LIỆU ĐẦU VÀO
    // =======================================================================
    // Kiểm tra tất cả các trường bắt buộc trước khi xử lý
    // Đây là tuyến phòng thủ đầu tiên (Defense in Depth — lớp Application)
    // =======================================================================

    const errors = [];

    if (!sender_account || typeof sender_account !== 'string' || !sender_account.trim()) {
      errors.push('Tài khoản người gửi (sender_account) là bắt buộc');
    }

    if (!receiver_account || typeof receiver_account !== 'string' || !receiver_account.trim()) {
      errors.push('Tài khoản người nhận (receiver_account) là bắt buộc');
    }

    // Validate số tiền: phải là số dương
    if (amount === undefined || amount === null || isNaN(Number(amount)) || Number(amount) <= 0) {
      errors.push('Số tiền (amount) phải là số dương lớn hơn 0');
    }

    // Validate số thẻ: chỉ chứa số, 13-19 chữ số (theo chuẩn ISO/IEC 7812)
    if (!card_number || typeof card_number !== 'string') {
      errors.push('Số thẻ (card_number) là bắt buộc');
    } else if (!/^\d{13,19}$/.test(card_number.replace(/\s/g, ''))) {
      errors.push('Số thẻ phải có 13-19 chữ số');
    }

    // Validate CVV: 3-4 chữ số (Visa/MC: 3, Amex: 4)
    if (!cvv || typeof cvv !== 'string') {
      errors.push('CVV là bắt buộc');
    } else if (!/^\d{3,4}$/.test(cvv)) {
      errors.push('CVV phải có 3-4 chữ số');
    }

    // Nếu có lỗi validation → trả về 400 Bad Request
    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Dữ liệu đầu vào không hợp lệ',
        errors,
      });
    }

    // =======================================================================
    // BƯỚC 2: MÃ HÓA DỮ LIỆU NHẠY CẢM
    // =======================================================================
    // Tất cả thông tin PII (Personally Identifiable Information) và thông tin
    // thẻ thanh toán PHẢI được mã hóa trước khi lưu vào database.
    //
    // Mỗi trường được mã hóa RIÊNG BIỆT với IV khác nhau, đảm bảo:
    //   - Cùng giá trị plaintext → ciphertext khác nhau (semantic security)
    //   - Compromise một trường không ảnh hưởng trường khác
    // =======================================================================

    const sanitizedCardNumber = card_number.replace(/\s/g, ''); // Xóa khoảng trắng
    const encryptedCardNumber = encryptToHex(sanitizedCardNumber, ENCRYPTION_KEY);
    const encryptedCvv = encryptToHex(cvv, ENCRYPTION_KEY);
    const encryptedSender = encryptToHex(sender_account.trim(), ENCRYPTION_KEY);
    const encryptedReceiver = encryptToHex(receiver_account.trim(), ENCRYPTION_KEY);

    // =======================================================================
    // BƯỚC 3: LƯU VÀO DATABASE
    // =======================================================================
    // Database chỉ nhận ciphertext hex — KHÔNG CÓ plaintext nào được ghi
    // Ngay cả DBA cũng không thể đọc được dữ liệu nếu không có encryption key
    // =======================================================================

    const Transaction = req.app.get('models').Transaction;

    const transaction = await Transaction.create({
      id: uuidv4(),
      sender_account: encryptedSender,
      receiver_account: encryptedReceiver,
      amount: Number(amount),
      card_number: encryptedCardNumber,
      cvv: encryptedCvv,
      status: 'pending',
    });

    // =======================================================================
    // BƯỚC 4: TRẢ VỀ RESPONSE
    // =======================================================================
    // QUAN TRỌNG: KHÔNG trả về plaintext số thẻ hoặc CVV trong response.
    // Chỉ trả về số thẻ đã mask và thông tin giao dịch cơ bản.
    // =======================================================================

    // Mask số thẻ: chỉ hiện 4 số cuối → ****1234
    const maskedCard = maskCardNumber(sanitizedCardNumber);

    return res.status(201).json({
      success: true,
      message: 'Giao dịch đã được tạo thành công',
      data: {
        id: transaction.id,
        sender_account: sender_account.trim(), // Trả lại plaintext cho người tạo
        receiver_account: receiver_account.trim(),
        amount: transaction.amount,
        card_number: maskedCard, // Đã mask — KHÔNG trả plaintext
        status: transaction.status,
        created_at: transaction.created_at,
      },
    });
  } catch (error) {
    // Log lỗi chi tiết (chỉ phía server) — KHÔNG gửi cho client
    console.error('[PaymentController] createTransaction error:', error.message);

    return res.status(500).json({
      success: false,
      message: 'Không thể tạo giao dịch. Vui lòng thử lại sau.',
    });
  }
}

/**
 * Lấy chi tiết một giao dịch và giải mã dữ liệu nhạy cảm.
 *
 * Chỉ người dùng đã xác thực mới được phép truy cập.
 * Dữ liệu nhạy cảm được giải mã từ ciphertext trong database.
 *
 * @param {import('express').Request} req - Express request object
 * @param {string} req.params.id - UUID của giao dịch cần xem
 * @param {import('express').Response} res - Express response object
 * @returns {Promise<void>}
 */
async function getTransaction(req, res) {
  try {
    const { id } = req.params;

    // Validate UUID format — ngăn SQL injection và truy vấn không hợp lệ
    if (!isValidUUID(id)) {
      return res.status(400).json({
        success: false,
        message: 'ID giao dịch không hợp lệ. Vui lòng kiểm tra lại.',
      });
    }

    const Transaction = req.app.get('models').Transaction;
    const transaction = await Transaction.findByPk(id);

    if (!transaction) {
      // Trả về 404 — KHÔNG phân biệt "không tồn tại" vs "không có quyền"
      // để tránh enumeration attack (kẻ tấn công dò ID hợp lệ)
      return res.status(404).json({
        success: false,
        message: 'Không tìm thấy giao dịch với ID đã cung cấp',
      });
    }

    // =======================================================================
    // GIẢI MÃ DỮ LIỆU NHẠY CẢM
    // =======================================================================
    // Chỉ giải mã khi cần hiển thị cho user hợp lệ.
    // Nếu giải mã thất bại (key sai hoặc dữ liệu bị tampering) → trả lỗi 500
    // =======================================================================

    let decryptedSender, decryptedReceiver, decryptedCard;

    try {
      decryptedSender = decryptFromHex(transaction.sender_account, ENCRYPTION_KEY);
      decryptedReceiver = decryptFromHex(transaction.receiver_account, ENCRYPTION_KEY);
      decryptedCard = decryptFromHex(transaction.card_number, ENCRYPTION_KEY);
    } catch (decryptError) {
      // Lỗi giải mã có thể do dữ liệu bị tampering trong database
      console.error('[PaymentController] Decryption failed — possible data tampering:', decryptError.message);
      return res.status(500).json({
        success: false,
        message: 'Lỗi xử lý dữ liệu giao dịch. Vui lòng liên hệ bộ phận hỗ trợ.',
      });
    }

    // Mask số thẻ ngay cả khi xem chi tiết — tuân thủ PCI-DSS
    const maskedCard = maskCardNumber(decryptedCard);

    return res.status(200).json({
      success: true,
      data: {
        id: transaction.id,
        sender_account: decryptedSender,
        receiver_account: decryptedReceiver,
        amount: transaction.amount,
        card_number: maskedCard,
        // CVV KHÔNG BAO GIỜ được trả về — ngay cả cho admin
        // Đây là yêu cầu bắt buộc của PCI-DSS Requirement 3.2
        status: transaction.status,
        created_at: transaction.created_at,
        updated_at: transaction.updated_at,
      },
    });
  } catch (error) {
    console.error('[PaymentController] getTransaction error:', error.message);

    return res.status(500).json({
      success: false,
      message: 'Không thể lấy thông tin giao dịch. Vui lòng thử lại sau.',
    });
  }
}

/**
 * Liệt kê tất cả giao dịch với thông tin thẻ đã mask.
 *
 * Hỗ trợ phân trang (pagination) để tránh trả về quá nhiều dữ liệu.
 * Số thẻ được giải mã rồi mask — client chỉ thấy ****1234.
 *
 * @param {import('express').Request} req - Express request object
 * @param {number} [req.query.page=1] - Số trang (bắt đầu từ 1)
 * @param {number} [req.query.limit=20] - Số giao dịch mỗi trang (tối đa 100)
 * @param {string} [req.query.status] - Lọc theo trạng thái (pending/completed/failed)
 * @param {import('express').Response} res - Express response object
 * @returns {Promise<void>}
 */
async function listTransactions(req, res) {
  try {
    // =======================================================================
    // PHÂN TRANG VÀ LỌC
    // =======================================================================
    // Giới hạn số bản ghi trả về để:
    //   - Tránh DoS bằng cách request số lượng lớn
    //   - Giảm tải cho database
    //   - Giảm thời gian giải mã (mỗi bản ghi cần giải mã nhiều trường)
    // =======================================================================

    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const offset = (page - 1) * limit;

    // Tạo điều kiện lọc
    const where = {};
    const validStatuses = ['pending', 'completed', 'failed'];
    if (req.query.status && validStatuses.includes(req.query.status)) {
      where.status = req.query.status;
    }

    const Transaction = req.app.get('models').Transaction;

    const { count, rows: transactions } = await Transaction.findAndCountAll({
      where,
      limit,
      offset,
      order: [['created_at', 'DESC']], // Giao dịch mới nhất lên đầu
      attributes: ['id', 'sender_account', 'receiver_account', 'amount',
                    'card_number', 'status', 'created_at'],
    });

    // =======================================================================
    // GIẢI MÃ VÀ MASK DỮ LIỆU
    // =======================================================================
    // Với mỗi giao dịch:
    //   1. Giải mã số thẻ → plaintext
    //   2. Mask plaintext → ****1234
    //   3. KHÔNG giải mã CVV — không bao giờ trả về CVV
    //   4. Giải mã tài khoản nếu cần hiển thị
    // =======================================================================

    const maskedTransactions = transactions.map((tx) => {
      let maskedCard = '****';
      let senderDisplay = '***';
      let receiverDisplay = '***';

      try {
        // Giải mã và mask số thẻ
        const plainCard = decryptFromHex(tx.card_number, ENCRYPTION_KEY);
        maskedCard = maskCardNumber(plainCard);

        // Giải mã tài khoản — trong list view cũng mask một phần
        const plainSender = decryptFromHex(tx.sender_account, ENCRYPTION_KEY);
        const plainReceiver = decryptFromHex(tx.receiver_account, ENCRYPTION_KEY);
        senderDisplay = maskAccountNumber(plainSender);
        receiverDisplay = maskAccountNumber(plainReceiver);
      } catch {
        // Nếu giải mã thất bại cho một bản ghi, vẫn trả về với giá trị mask
        // Ghi log để điều tra — có thể dữ liệu bị corrupted hoặc key đã thay đổi
        console.error(`[PaymentController] Decrypt failed for transaction ${tx.id}`);
      }

      return {
        id: tx.id,
        sender_account: senderDisplay,
        receiver_account: receiverDisplay,
        amount: tx.amount,
        card_number: maskedCard,
        status: tx.status,
        created_at: tx.created_at,
      };
    });

    return res.status(200).json({
      success: true,
      data: maskedTransactions,
      pagination: {
        total: count,
        page,
        limit,
        totalPages: Math.ceil(count / limit),
      },
    });
  } catch (error) {
    console.error('[PaymentController] listTransactions error:', error.message);

    return res.status(500).json({
      success: false,
      message: 'Không thể lấy danh sách giao dịch. Vui lòng thử lại sau.',
    });
  }
}

// ===========================================================================
// HÀM TIỆN ÍCH NỘI BỘ
// ===========================================================================

/**
 * Mask số thẻ thanh toán — chỉ hiện 4 số cuối.
 *
 * Tuân thủ PCI-DSS Requirement 3.3: khi hiển thị PAN, chỉ được hiện
 * tối đa 6 số đầu và 4 số cuối. Ở đây ta chỉ hiện 4 số cuối cho an toàn hơn.
 *
 * @param {string} cardNumber - Số thẻ plaintext (13-19 chữ số)
 * @returns {string} Số thẻ đã mask, ví dụ: "****1234"
 */
function maskCardNumber(cardNumber) {
  if (!cardNumber || cardNumber.length < 4) {
    return '****';
  }
  const lastFour = cardNumber.slice(-4);
  return `****${lastFour}`;
}

/**
 * Mask số tài khoản — hiện 3 ký tự cuối.
 *
 * @param {string} accountNumber - Số tài khoản plaintext
 * @returns {string} Tài khoản đã mask, ví dụ: "***456"
 */
function maskAccountNumber(accountNumber) {
  if (!accountNumber || accountNumber.length < 3) {
    return '***';
  }
  const lastThree = accountNumber.slice(-3);
  return `***${lastThree}`;
}

/**
 * Kiểm tra chuỗi có phải UUID v4 hợp lệ không.
 *
 * Regex pattern kiểm tra format UUID v4:
 *   xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx
 *
 * @param {string} str - Chuỗi cần kiểm tra
 * @returns {boolean} true nếu là UUID v4 hợp lệ
 */
function isValidUUID(str) {
  if (!str || typeof str !== 'string') return false;
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(str);
}

// ===========================================================================
// EXPORT
// ===========================================================================

module.exports = {
  createTransaction,
  getTransaction,
  listTransactions,
};
