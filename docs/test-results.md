# Kết Quả Kiểm Thử Hệ Thống Bảo Mật

## Thông Tin Chung

| Mục | Chi tiết |
|---|---|
| **Dự án** | Hệ Thống Thanh Toán Microservice Bảo Mật Đa Tầng |
| **Ngày kiểm thử** | ___/___/2025 |
| **Người kiểm thử** | Khuất Minh Hoàng & Đỗ Trọng Đức |
| **Môi trường** | Kubernetes (Minikube/Kind) trên máy cục bộ |
| **Phiên bản** | 1.0.0 |

---

## 1. Kiểm Thử Xác Thực và Phân Quyền (Authentication & Authorization)

**Script**: `tests/auth-test/test-auth.sh`

| Mã TC | Mô tả | Kết quả mong đợi | Kết quả thực tế | Trạng thái |
|---|---|---|---|---|
| TC-01 | Request không có JWT token | HTTP 401 Unauthorized | | ☐ PASS / ☐ FAIL |
| TC-02 | Request với token đã hết hạn | HTTP 401 Unauthorized | | ☐ PASS / ☐ FAIL |
| TC-03 | Request với token không hợp lệ | HTTP 403 Forbidden | | ☐ PASS / ☐ FAIL |
| TC-04 | Request với sai role (user → admin) | HTTP 403 Forbidden | | ☐ PASS / ☐ FAIL |
| TC-05 | Request với token hợp lệ | HTTP 200 OK | | ☐ PASS / ☐ FAIL |
| TC-06 | Đăng ký user mới | HTTP 201 Created | | ☐ PASS / ☐ FAIL |
| TC-07 | Đăng nhập đúng thông tin | HTTP 200 + JWT token | | ☐ PASS / ☐ FAIL |
| TC-08 | Đăng nhập sai mật khẩu | HTTP 401 Unauthorized | | ☐ PASS / ☐ FAIL |

### Ảnh chụp kết quả

<!-- Chèn ảnh chụp màn hình kết quả chạy test-auth.sh tại đây -->
> 📸 *Chèn ảnh chụp màn hình kết quả TC-01 đến TC-08*

```
[Dán output từ terminal tại đây]
```

### Phân tích

- **Tổng số test**: 8
- **PASS**: ___
- **FAIL**: ___
- **Nhận xét**: _______________________________________________

---

## 2. Kiểm Thử Network Policies (Zero Trust)

**Script**: `tests/network-test/test-network.sh`

| Mã TC | Mô tả | Kết quả mong đợi | Kết quả thực tế | Trạng thái |
|---|---|---|---|---|
| TC-01 | Payment Pod → PostgreSQL (port 5432) | Kết nối THÀNH CÔNG ✅ | | ☐ PASS / ☐ FAIL |
| TC-02 | Gateway Pod → Payment Service (port 3002) | Kết nối THÀNH CÔNG ✅ | | ☐ PASS / ☐ FAIL |
| TC-03 | Random Pod → Payment Service (port 3002) | Kết nối BỊ CHẶN ❌ | | ☐ PASS / ☐ FAIL |
| TC-04 | Payment Pod → Auth Service (port 3001) | Kết nối BỊ CHẶN ❌ | | ☐ PASS / ☐ FAIL |
| TC-05 | External Pod → PostgreSQL (port 5432) | Kết nối BỊ CHẶN ❌ | | ☐ PASS / ☐ FAIL |

### Ảnh chụp kết quả

<!-- Chèn ảnh chụp màn hình kết quả chạy test-network.sh tại đây -->
> 📸 *Chèn ảnh chụp màn hình kết quả TC-01 đến TC-05*

```
[Dán output từ terminal tại đây]
```

### Sơ đồ minh họa Network Policies

```
  ┌──────────┐     ✅     ┌──────────┐     ✅     ┌──────────┐
  │ Gateway  │───────────→│ Payment  │───────────→│PostgreSQL│
  │ Pod      │            │ Pod      │            │ Pod      │
  └──────────┘            └──────────┘            └──────────┘
                               ▲                       ▲
                               │ ❌                     │ ❌
                          ┌────┴─────┐            ┌────┴─────┐
                          │ Random   │            │ Random   │
                          │ Pod      │            │ Pod      │
                          └──────────┘            └──────────┘
```

### Phân tích

- **Tổng số test**: 5
- **PASS**: ___
- **FAIL**: ___
- **Nhận xét**: _______________________________________________

---

## 3. Kiểm Thử Mã Hóa AES-256-GCM (Encryption at Rest)

**Script**: `tests/encryption-test/test-encryption.sh`

| Mã TC | Mô tả | Kết quả mong đợi | Kết quả thực tế | Trạng thái |
|---|---|---|---|---|
| TC-01 | Tạo giao dịch qua API với dữ liệu thẻ | HTTP 201 + Transaction ID | | ☐ PASS / ☐ FAIL |
| TC-02 | Truy vấn database trực tiếp (kubectl exec) | Lấy được dữ liệu raw từ DB | | ☐ PASS / ☐ FAIL |
| TC-03 | Cột card_number chứa hex ciphertext | Giá trị ≠ plaintext, là hex string | | ☐ PASS / ☐ FAIL |
| TC-04 | Cột cvv chứa hex ciphertext | Giá trị ≠ "123", là hex string | | ☐ PASS / ☐ FAIL |
| TC-05 | API trả về dữ liệu giải mã cho user có quyền | HTTP 200 + masked/decrypted data | | ☐ PASS / ☐ FAIL |

### Ảnh chụp kết quả

<!-- Chèn ảnh chụp so sánh plaintext vs ciphertext tại đây -->
> 📸 *Chèn ảnh chụp so sánh:*
> - Dữ liệu gửi qua API (plaintext): `4532015112830366`
> - Dữ liệu trong database (ciphertext): `a3f2b8c9d1e4...`
> - Dữ liệu API trả về (masked): `****0366`

```
[Dán output từ terminal tại đây]
```

### So sánh Plaintext vs Ciphertext

| Trường | Giá trị gửi đi (Plaintext) | Giá trị trong DB (Ciphertext) | Mã hóa? |
|---|---|---|---|
| card_number | 4532015112830366 | ___ (hex string) | ☐ Có / ☐ Không |
| cvv | 123 | ___ (hex string) | ☐ Có / ☐ Không |
| card_holder | NGUYEN VAN TEST | ___ | ☐ Không mã hóa |
| amount | 500000 | 500000 | ☐ Không mã hóa |

### Phân tích

- **Tổng số test**: 5
- **PASS**: ___
- **FAIL**: ___
- **Nhận xét**: _______________________________________________

---

## 4. Kiểm Thử CI/CD Security Gate (Trivy Scanner)

**Script**: `tests/cicd-test/test-trivy.sh`

| Mã TC | Mô tả | Kết quả mong đợi | Kết quả thực tế | Trạng thái |
|---|---|---|---|---|
| TC-01 | Build image với base có lỗ hổng (node:14) | Trivy phát hiện CVE | | ☐ PASS / ☐ FAIL |
| TC-02 | Build image với base sạch (node:20-alpine) | Trivy pass (0 CRITICAL) | | ☐ PASS / ☐ FAIL |
| TC-03 | Security Gate chặn khi có CRITICAL CVE | Pipeline bị dừng (exit 1) | | ☐ PASS / ☐ FAIL |

### Ảnh chụp kết quả

<!-- Chèn ảnh chụp kết quả Trivy scan tại đây -->
> 📸 *Chèn ảnh chụp:*
> - Kết quả quét image vulnerable (danh sách CVE)
> - Kết quả quét image clean
> - Security Gate output (CHẶN/CHO PHÉP)

```
[Dán output từ terminal tại đây]
```

### Thống kê CVE phát hiện

| Image | CRITICAL | HIGH | MEDIUM | LOW | Tổng |
|---|---|---|---|---|---|
| node:14 (vulnerable) | ___ | ___ | ___ | ___ | ___ |
| node:20-alpine (clean) | ___ | ___ | ___ | ___ | ___ |
| gateway:latest | ___ | ___ | ___ | ___ | ___ |
| auth:latest | ___ | ___ | ___ | ___ | ___ |
| payment:latest | ___ | ___ | ___ | ___ | ___ |

### Top 5 CVE phát hiện (nếu có)

| CVE ID | Package | Severity | Mô tả | Bản vá |
|---|---|---|---|---|
| ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ |

### Phân tích

- **Tổng số test**: 3
- **PASS**: ___
- **FAIL**: ___
- **Nhận xét**: _______________________________________________

---

## 5. Tổng Kết Toàn Bộ

### Thống kê tổng hợp

| Nhóm kiểm thử | Tổng TC | PASS | FAIL | Tỷ lệ PASS |
|---|---|---|---|---|
| Xác thực & Phân quyền | 8 | ___ | ___ | ___% |
| Network Policies | 5 | ___ | ___ | ___% |
| Mã hóa AES-256-GCM | 5 | ___ | ___ | ___% |
| CI/CD Security Gate | 3 | ___ | ___ | ___% |
| **TỔNG** | **21** | **___** | **___** | **___%** |

### Đánh giá theo tầng bảo mật

| Tầng bảo mật | Trạng thái | Ghi chú |
|---|---|---|
| Tầng 1: Application Security | ☐ ĐẠT / ☐ KHÔNG ĐẠT | JWT, AES-256-GCM, Input Validation |
| Tầng 2: Infrastructure Security | ☐ ĐẠT / ☐ KHÔNG ĐẠT | Network Policies, RBAC, Sealed Secrets |
| Tầng 3: DevSecOps | ☐ ĐẠT / ☐ KHÔNG ĐẠT | Trivy Scan, Security Gate, CI/CD |

### Kết luận

_______________________________________________
_______________________________________________
_______________________________________________

### Đề xuất cải thiện

1. _______________________________________________
2. _______________________________________________
3. _______________________________________________

---

## Phụ Lục

### A. Môi trường kiểm thử

| Thành phần | Phiên bản |
|---|---|
| OS | ___ |
| Docker | ___ |
| Kubernetes | ___ |
| kubectl | ___ |
| Minikube/Kind | ___ |
| Node.js | ___ |
| Trivy | ___ |

### B. Lệnh chạy kiểm thử

```bash
# Kiểm thử xác thực
chmod +x tests/auth-test/test-auth.sh
BASE_URL=http://localhost:3000/api ./tests/auth-test/test-auth.sh

# Kiểm thử Network Policies
chmod +x tests/network-test/test-network.sh
K8S_NAMESPACE=payment-system ./tests/network-test/test-network.sh

# Kiểm thử mã hóa
chmod +x tests/encryption-test/test-encryption.sh
BASE_URL=http://localhost:3000/api ./tests/encryption-test/test-encryption.sh

# Kiểm thử CI/CD Security Gate
chmod +x tests/cicd-test/test-trivy.sh
./tests/cicd-test/test-trivy.sh
```

### C. Ảnh chụp bổ sung

<!-- Chèn thêm ảnh chụp tại đây nếu cần -->
> 📸 *Các ảnh chụp bổ sung*
