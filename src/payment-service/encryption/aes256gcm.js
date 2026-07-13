'use strict';

/**
 * @fileoverview Module mã hóa AES-256-GCM cho dữ liệu thanh toán nhạy cảm.
 *
 * AES-256-GCM (Advanced Encryption Standard — Galois/Counter Mode) là thuật toán
 * mã hóa đối xứng (symmetric encryption) cung cấp cả tính BÍ MẬT (confidentiality)
 * và tính TOÀN VẸN (integrity/authenticity) cho dữ liệu.
 *
 * === TẠI SAO CHỌN AES-256-GCM? ===
 *
 * 1. AUTHENTICATED ENCRYPTION (Mã hóa có xác thực):
 *    - GCM mode tạo ra Authentication Tag cùng với ciphertext.
 *    - Auth Tag cho phép phát hiện nếu ciphertext bị thay đổi (tampering).
 *    - Các mode khác (CBC, ECB) KHÔNG có tính năng này, cần thêm HMAC riêng.
 *
 * 2. ĐỘ DÀI KHÓA 256-BIT:
 *    - Cung cấp 2^256 tổ hợp khóa — không thể brute-force với công nghệ hiện tại.
 *    - Đáp ứng yêu cầu PCI-DSS cho mã hóa dữ liệu thẻ thanh toán.
 *
 * 3. HIỆU SUẤT CAO:
 *    - GCM hỗ trợ xử lý song song (parallelizable), nhanh hơn CBC.
 *    - Tận dụng AES-NI instruction set trên CPU hiện đại.
 *
 * === CẤU TRÚC DỮ LIỆU MÃ HÓA ===
 *
 * Chuỗi hex đầu ra có format: IV (24 hex) + AuthTag (32 hex) + EncryptedData
 *   - IV:            12 bytes = 24 ký tự hex
 *   - Auth Tag:      16 bytes = 32 ký tự hex
 *   - Encrypted Data: biến đổi tùy theo plaintext
 *
 * @module payment-service/encryption/aes256gcm
 */

const crypto = require('crypto');

// ---------------------------------------------------------------------------
// HẰNG SỐ CẤU HÌNH
// ---------------------------------------------------------------------------

/**
 * Thuật toán mã hóa: AES-256-GCM
 * - AES: Advanced Encryption Standard — chuẩn mã hóa được NIST phê duyệt
 * - 256: độ dài khóa 256 bit (32 bytes)
 * - GCM: Galois/Counter Mode — mode hoạt động cung cấp authenticated encryption
 * @constant {string}
 */
const ALGORITHM = 'aes-256-gcm';

/**
 * Độ dài IV (Initialization Vector): 12 bytes = 96 bits.
 *
 * NIST SP 800-38D khuyến nghị IV 96-bit cho GCM vì:
 *   - Hiệu suất tối ưu: không cần thêm bước hash IV
 *   - An toàn: với IV 96-bit, có thể mã hóa tới 2^32 block mà không lo collision
 *
 * IV PHẢI là DUY NHẤT cho mỗi lần mã hóa với cùng một key.
 * Sử dụng crypto.randomBytes() đảm bảo tính ngẫu nhiên mạnh (CSPRNG).
 *
 * @constant {number}
 */
const IV_LENGTH = 12;

/**
 * Độ dài Authentication Tag: 16 bytes = 128 bits.
 *
 * Auth Tag càng dài → càng khó giả mạo. 128-bit là giá trị tối đa và an toàn nhất.
 * Auth Tag được tạo tự động bởi GCM mode trong quá trình mã hóa.
 *
 * @constant {number}
 */
const AUTH_TAG_LENGTH = 16;

// ---------------------------------------------------------------------------
// HÀM MÃ HÓA (ENCRYPT)
// ---------------------------------------------------------------------------

/**
 * Mã hóa plaintext bằng AES-256-GCM.
 *
 * Quy trình mã hóa:
 *   1. Tạo IV ngẫu nhiên 12 bytes bằng CSPRNG (Cryptographically Secure PRNG)
 *   2. Tạo cipher object với algorithm, key, và IV
 *   3. Mã hóa plaintext → ciphertext
 *   4. Lấy Authentication Tag (tự động tạo bởi GCM)
 *   5. Ghép IV + AuthTag + Ciphertext thành một chuỗi hex duy nhất
 *
 * @param {string} plaintext - Dữ liệu cần mã hóa (ví dụ: số thẻ, CVV)
 * @param {string} key - Khóa mã hóa dạng hex string (64 ký tự hex = 32 bytes)
 * @returns {{ iv: string, encryptedData: string, authTag: string }} Object chứa
 *   các thành phần mã hóa ở dạng hex string
 * @throws {Error} Nếu key không đúng độ dài hoặc plaintext rỗng
 *
 * @example
 * const { encrypt } = require('./aes256gcm');
 * const key = 'a1b2c3d4...'; // 64 hex chars
 * const result = encrypt('4111111111111111', key);
 * // result = { iv: '...', encryptedData: '...', authTag: '...' }
 */
function encrypt(plaintext, key) {
  // --- Bước 0: Kiểm tra đầu vào ---
  if (!plaintext || typeof plaintext !== 'string') {
    throw new Error('Plaintext phải là chuỗi không rỗng');
  }

  if (!key || typeof key !== 'string') {
    throw new Error('Key phải là chuỗi hex không rỗng');
  }

  // Chuyển key từ hex string → Buffer và kiểm tra độ dài
  const keyBuffer = Buffer.from(key, 'hex');
  if (keyBuffer.length !== 32) {
    throw new Error(
      `Key phải có độ dài 32 bytes (256 bits). Nhận được: ${keyBuffer.length} bytes`
    );
  }

  // --- Bước 1: Tạo IV ngẫu nhiên ---
  // crypto.randomBytes() sử dụng CSPRNG của hệ điều hành
  // (urandom trên Linux, CryptGenRandom trên Windows)
  // Mỗi lần mã hóa tạo IV mới → đảm bảo cùng plaintext cho ra ciphertext khác nhau
  const iv = crypto.randomBytes(IV_LENGTH);

  // --- Bước 2: Tạo cipher ---
  // createCipheriv: tạo cipher với IV do ta cung cấp (iv = Initialization Vector)
  // Tham số: algorithm, key (Buffer), iv (Buffer), options
  const cipher = crypto.createCipheriv(ALGORITHM, keyBuffer, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  // --- Bước 3: Mã hóa dữ liệu ---
  // update(): xử lý dữ liệu đầu vào, trả về phần ciphertext tương ứng
  // final(): xử lý phần dữ liệu còn lại (padding), trả về phần ciphertext cuối
  // 'utf8' → encoding đầu vào (plaintext là UTF-8)
  // 'hex' → encoding đầu ra (ciphertext ở dạng hex)
  let encryptedData = cipher.update(plaintext, 'utf8', 'hex');
  encryptedData += cipher.final('hex');

  // --- Bước 4: Lấy Authentication Tag ---
  // Auth Tag được GCM tự động tính toán dựa trên:
  //   - Key, IV, plaintext, và Additional Authenticated Data (AAD) nếu có
  // Auth Tag dùng để xác minh: ciphertext KHÔNG bị thay đổi sau khi mã hóa
  const authTag = cipher.getAuthTag();

  // --- Bước 5: Trả về kết quả ---
  // Tất cả đều ở dạng hex string để lưu trữ an toàn trong database
  return {
    iv: iv.toString('hex'),
    encryptedData,
    authTag: authTag.toString('hex'),
  };
}

// ---------------------------------------------------------------------------
// HÀM GIẢI MÃ (DECRYPT)
// ---------------------------------------------------------------------------

/**
 * Giải mã ciphertext đã được mã hóa bằng AES-256-GCM.
 *
 * Quy trình giải mã:
 *   1. Tách IV, AuthTag, EncryptedData từ chuỗi hex đầu vào
 *   2. Tạo decipher object với algorithm, key, và IV
 *   3. Đặt Auth Tag để GCM xác minh tính toàn vẹn
 *   4. Giải mã ciphertext → plaintext
 *   5. final() sẽ FAIL nếu Auth Tag không khớp → phát hiện tampering
 *
 * @param {string} ciphertext - Chuỗi hex chứa IV + AuthTag + EncryptedData
 *   Format: [IV 24 hex][AuthTag 32 hex][EncryptedData ...]
 * @param {string} key - Khóa giải mã dạng hex string (phải giống key đã dùng khi mã hóa)
 * @returns {string} Plaintext gốc (ví dụ: số thẻ, CVV)
 * @throws {Error} Nếu ciphertext bị tampering (Auth Tag không khớp) hoặc key sai
 *
 * @example
 * const { decrypt } = require('./aes256gcm');
 * const plaintext = decrypt(storedCiphertext, key);
 * // plaintext = '4111111111111111'
 */
function decrypt(ciphertext, key) {
  // --- Bước 0: Kiểm tra đầu vào ---
  if (!ciphertext || typeof ciphertext !== 'string') {
    throw new Error('Ciphertext phải là chuỗi hex không rỗng');
  }

  if (!key || typeof key !== 'string') {
    throw new Error('Key phải là chuỗi hex không rỗng');
  }

  const keyBuffer = Buffer.from(key, 'hex');
  if (keyBuffer.length !== 32) {
    throw new Error(
      `Key phải có độ dài 32 bytes (256 bits). Nhận được: ${keyBuffer.length} bytes`
    );
  }

  // --- Bước 1: Tách các thành phần từ ciphertext ---
  // Cấu trúc hex string: [IV][AuthTag][EncryptedData]
  //   IV:        12 bytes = 24 ký tự hex
  //   AuthTag:   16 bytes = 32 ký tự hex
  //   Encrypted: phần còn lại
  const ivHexLength = IV_LENGTH * 2;           // 24
  const authTagHexLength = AUTH_TAG_LENGTH * 2; // 32

  // Kiểm tra ciphertext có đủ dài không (ít nhất phải có IV + AuthTag)
  const minLength = ivHexLength + authTagHexLength;
  if (ciphertext.length < minLength) {
    throw new Error(
      `Ciphertext quá ngắn. Tối thiểu ${minLength} ký tự hex, nhận được ${ciphertext.length}`
    );
  }

  // Tách IV, AuthTag, và EncryptedData
  const ivHex = ciphertext.substring(0, ivHexLength);
  const authTagHex = ciphertext.substring(ivHexLength, ivHexLength + authTagHexLength);
  const encryptedDataHex = ciphertext.substring(ivHexLength + authTagHexLength);

  // Chuyển từ hex string → Buffer
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  // --- Bước 2: Tạo decipher ---
  const decipher = crypto.createDecipheriv(ALGORITHM, keyBuffer, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  // --- Bước 3: Đặt Auth Tag ---
  // setAuthTag() PHẢI được gọi TRƯỚC khi gọi final()
  // GCM sẽ so sánh tag này với tag tính toán được từ ciphertext
  // Nếu không khớp → final() ném lỗi "Unsupported state or unable to authenticate data"
  decipher.setAuthTag(authTag);

  // --- Bước 4: Giải mã ---
  try {
    let plaintext = decipher.update(encryptedDataHex, 'hex', 'utf8');
    // final() thực hiện:
    //   a. Giải mã phần dữ liệu cuối cùng
    //   b. Xác minh Auth Tag — NẾU THẤT BẠI → ném lỗi (dữ liệu đã bị thay đổi)
    plaintext += decipher.final('utf8');
    return plaintext;
  } catch (error) {
    // Lỗi xác thực: ciphertext hoặc key đã bị thay đổi
    // KHÔNG trả về thông tin chi tiết để tránh oracle attack
    throw new Error('Giải mã thất bại — dữ liệu có thể đã bị thay đổi hoặc key không đúng');
  }
}

// ---------------------------------------------------------------------------
// HÀM TIỆN ÍCH
// ---------------------------------------------------------------------------

/**
 * Mã hóa plaintext và trả về một chuỗi hex duy nhất chứa tất cả thông tin
 * cần thiết để giải mã (IV + AuthTag + EncryptedData).
 *
 * Đây là hàm wrapper tiện dụng để lưu trực tiếp vào database dưới dạng
 * một cột VARCHAR/TEXT duy nhất.
 *
 * @param {string} plaintext - Dữ liệu cần mã hóa
 * @param {string} key - Khóa mã hóa (hex string, 64 ký tự)
 * @returns {string} Chuỗi hex: IV + AuthTag + EncryptedData
 */
function encryptToHex(plaintext, key) {
  const { iv, authTag, encryptedData } = encrypt(plaintext, key);
  // Ghép: IV (24 hex) + AuthTag (32 hex) + EncryptedData (biến đổi)
  return iv + authTag + encryptedData;
}

/**
 * Giải mã chuỗi hex (output của encryptToHex) về plaintext gốc.
 *
 * @param {string} hexString - Chuỗi hex chứa IV + AuthTag + EncryptedData
 * @param {string} key - Khóa giải mã (hex string, 64 ký tự)
 * @returns {string} Plaintext gốc
 */
function decryptFromHex(hexString, key) {
  return decrypt(hexString, key);
}

// ---------------------------------------------------------------------------
// EXPORT
// ---------------------------------------------------------------------------

module.exports = {
  encrypt,
  decrypt,
  encryptToHex,
  decryptFromHex,
  ALGORITHM,
  IV_LENGTH,
  AUTH_TAG_LENGTH,
};
