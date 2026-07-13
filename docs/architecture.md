# Kiến Trúc Hệ Thống Thanh Toán Microservice Bảo Mật Đa Tầng

## 1. Tổng Quan Hệ Thống

Hệ thống thanh toán được thiết kế theo kiến trúc **microservices**, triển khai trên **Kubernetes**, với **3 tầng bảo mật** tích hợp xuyên suốt từ mã nguồn đến hạ tầng.

### Sơ đồ kiến trúc tổng quan

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        INTERNET / CLIENT                                    │
│                    (Web Browser / Mobile App)                               │
└──────────────────────────────┬──────────────────────────────────────────────┘
                               │ HTTPS (TLS 1.3)
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      KUBERNETES CLUSTER                                     │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    INGRESS CONTROLLER                                 │  │
│  │              (TLS Termination + Rate Limiting)                        │  │
│  └──────────────────────────────┬────────────────────────────────────────┘  │
│                                 │                                           │
│  ┌──────────────────────────────▼────────────────────────────────────────┐  │
│  │              API GATEWAY SERVICE (Port 3000)                          │  │
│  │  ┌─────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────────────┐  │  │
│  │  │ Rate Limiter│ │ Helmet.js    │ │ CORS Policy  │ │ Request     │  │  │
│  │  │ (100 req/15m)│ │ (HTTP Hdrs) │ │ (Whitelist)  │ │ Validation  │  │  │
│  │  └─────────────┘ └──────────────┘ └──────────────┘ └─────────────┘  │  │
│  └────────────┬─────────────────────────────────┬────────────────────────┘  │
│               │                                 │                           │
│    Network    │  Policy: gateway→auth ✅        │  Policy: gateway→payment ✅│
│               │                                 │                           │
│  ┌────────────▼──────────────┐   ┌──────────────▼────────────────────────┐  │
│  │  AUTH SERVICE (Port 3001) │   │  PAYMENT SERVICE (Port 3002)          │  │
│  │  ┌──────────────────────┐ │   │  ┌──────────────────────────────────┐ │  │
│  │  │ JWT Authentication   │ │   │  │ AES-256-GCM Encryption          │ │  │
│  │  │ bcrypt Password Hash │ │   │  │ Transaction Processing          │ │  │
│  │  │ RBAC Authorization   │ │   │  │ Input Validation (Joi)          │ │  │
│  │  │ Token Refresh/Revoke │ │   │  │ Card Data Masking               │ │  │
│  │  └──────────────────────┘ │   │  └──────────────────────────────────┘ │  │
│  └───────────────────────────┘   └──────────────┬────────────────────────┘  │
│                                                  │                          │
│                               Network Policy:    │ payment→postgres ✅      │
│                               random→postgres ❌ │                          │
│                                                  │                          │
│  ┌───────────────────────────────────────────────▼───────────────────────┐  │
│  │                    POSTGRESQL DATABASE                                │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │  Encrypted at Rest (AES-256-GCM)                               │  │  │
│  │  │  Sealed Secrets for Credentials                                 │  │  │
│  │  │  Network Policy: Chỉ Payment Service được truy cập             │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                     DevSecOps Pipeline                                │  │
│  │  BUILD → TEST → TRIVY SCAN → SECURITY GATE → STAGING → PRODUCTION   │  │
│  │    │       │        │             │              │           │        │  │
│  │  Docker  Unit    Quét CVE    Chặn nếu      kubectl      Manual       │  │
│  │  Build   Test    CRITICAL    CRITICAL       apply      Approval      │  │
│  │          +       + HIGH      tồn tại                                 │  │
│  │        Coverage                                                       │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 2. Mô Tả Các Thành Phần

### 2.1 API Gateway Service (Port 3000)

**Vai trò**: Điểm vào duy nhất (Single Entry Point) cho toàn bộ hệ thống.

**Chức năng bảo mật**:
| Thành phần | Mô tả | Mục đích |
|---|---|---|
| **Rate Limiter** | Giới hạn 100 request / 15 phút / IP | Chống brute force, DDoS |
| **Helmet.js** | Thiết lập HTTP security headers | Chống XSS, Clickjacking, MIME sniffing |
| **CORS Policy** | Chỉ cho phép domain trong whitelist | Chống Cross-Site Request Forgery |
| **Request Validation** | Kiểm tra input với Joi schema | Chống SQL Injection, NoSQL Injection |
| **Request Logging** | Ghi log tất cả request (Morgan) | Audit trail, phát hiện tấn công |

**Luồng xử lý request**:
```
Client Request
  → Rate Limiter (kiểm tra tần suất)
  → Helmet (thêm security headers)
  → CORS (kiểm tra origin)
  → Auth Middleware (xác thực JWT)
  → Route Handler (chuyển tiếp đến service phù hợp)
  → Response (trả kết quả)
```

### 2.2 Authentication Service (Port 3001)

**Vai trò**: Quản lý xác thực (Authentication) và phân quyền (Authorization).

**Chức năng chi tiết**:

| Tính năng | Chi tiết kỹ thuật |
|---|---|
| **Đăng ký** | Mã hóa mật khẩu bằng bcrypt (salt rounds: 12) |
| **Đăng nhập** | Xác thực credentials → Cấp JWT token (1 giờ) |
| **JWT Token** | Algorithm: HS256, Payload: userId + role + iat + exp |
| **RBAC** | 3 roles: admin, user, viewer — mỗi role có permissions khác nhau |
| **Token Refresh** | Cấp token mới trước khi token cũ hết hạn |

**Luồng xác thực JWT**:
```
                   ┌─────────────┐
                   │  Client gửi │
                   │  credentials│
                   └──────┬──────┘
                          │
                   ┌──────▼──────┐
                   │  Kiểm tra   │
                   │  email/pass │
                   └──────┬──────┘
                          │
                ┌─────────▼─────────┐
                │ bcrypt.compare()  │
                │ hash vs password  │
                └─────────┬─────────┘
                          │
              ┌───────────▼───────────┐
              │ YES: Cấp JWT token    │
              │ NO:  Return 401       │
              └───────────┬───────────┘
                          │
              ┌───────────▼───────────┐
              │  Token = {            │
              │    userId,            │
              │    role,              │
              │    iat (issued at),   │
              │    exp (1h from now)  │
              │  }                    │
              └───────────────────────┘
```

### 2.3 Payment Service (Port 3002)

**Vai trò**: Xử lý giao dịch thanh toán với mã hóa dữ liệu nhạy cảm.

**Chức năng bảo mật**:

| Tính năng | Chi tiết |
|---|---|
| **AES-256-GCM** | Mã hóa số thẻ và CVV trước khi lưu DB |
| **IV ngẫu nhiên** | Mỗi lần mã hóa dùng IV (Initialization Vector) khác nhau |
| **Auth Tag** | GCM mode cung cấp authentication tag → xác minh tính toàn vẹn |
| **Input Validation** | Kiểm tra định dạng thẻ (Luhn algorithm), CVV, ngày hết hạn |
| **Data Masking** | API response chỉ hiển thị 4 số cuối thẻ (****0366) |

**Luồng mã hóa AES-256-GCM**:
```
  Dữ liệu thẻ (plaintext)
        │
        ▼
  ┌─────────────────┐
  │ Tạo IV ngẫu     │  ← 12 bytes ngẫu nhiên (crypto.randomBytes)
  │ nhiên            │
  └────────┬────────┘
           │
  ┌────────▼────────┐
  │ AES-256-GCM     │  ← Key: 32 bytes từ Sealed Secret
  │ Encrypt         │  ← IV: 12 bytes ngẫu nhiên
  │                 │  → Ciphertext + Auth Tag (16 bytes)
  └────────┬────────┘
           │
  ┌────────▼────────┐
  │ Lưu vào DB:     │
  │ iv:authTag:      │
  │ ciphertext       │
  │ (hex format)     │
  └─────────────────┘
```

### 2.4 PostgreSQL Database

**Vai trò**: Lưu trữ dữ liệu giao dịch thanh toán.

**Bảo mật**:
- Dữ liệu nhạy cảm được mã hóa TRƯỚC khi lưu (Encryption at Application Level)
- Credentials được quản lý qua Kubernetes Sealed Secrets
- Network Policy chỉ cho phép Payment Service kết nối (port 5432)
- Không pod nào khác có thể truy cập trực tiếp database

## 3. Luồng Dữ Liệu (Data Flow)

### 3.1 Luồng tạo giao dịch thanh toán

```
┌──────┐    HTTPS     ┌─────────┐   HTTP    ┌──────┐  Verify  ┌──────┐
│Client│──────────────→│ Gateway │──────────→│ Auth │─────────→│ JWT  │
│      │              │         │           │      │  Token   │Verify│
└──────┘              └────┬────┘           └──────┘          └──┬───┘
                           │                                     │
                           │  ← Token Valid ─────────────────────┘
                           │
                      ┌────▼────┐
                      │ Payment │  1. Validate input (Joi)
                      │ Service │  2. Encrypt card_number (AES-256-GCM)
                      │         │  3. Encrypt CVV (AES-256-GCM)
                      └────┬────┘  4. Create transaction record
                           │
                      ┌────▼────┐
                      │PostgreSQL│  Lưu: encrypted card, encrypted CVV,
                      │         │  amount, timestamp, status
                      └─────────┘
```

### 3.2 Luồng truy vấn giao dịch

```
Client → Gateway → Auth (verify JWT + check role)
                         ↓
                    Payment Service
                    1. Query DB (encrypted data)
                    2. Decrypt card_number
                    3. Mask card: ****0366
                    4. Return masked response
                         ↓
                    Client nhận: { card: "****0366", amount: 500000 }
```

## 4. Điểm Kiểm Tra Bảo Mật (Security Checkpoints)

### Checkpoint tại mỗi tầng:

```
                          REQUEST FLOW
                              │
  ┌───────────────────────────▼────────────────────────────┐
  │ CHECKPOINT 1: Network Level (Ingress)                  │
  │ ✓ TLS 1.3 termination                                 │
  │ ✓ IP whitelist (nếu cấu hình)                         │
  │ ✓ DDoS protection                                     │
  └───────────────────────────┬────────────────────────────┘
                              │
  ┌───────────────────────────▼────────────────────────────┐
  │ CHECKPOINT 2: Application Level (Gateway)              │
  │ ✓ Rate limiting (100 req/15min)                        │
  │ ✓ Security headers (Helmet.js)                         │
  │ ✓ CORS validation                                      │
  │ ✓ Input sanitization                                   │
  └───────────────────────────┬────────────────────────────┘
                              │
  ┌───────────────────────────▼────────────────────────────┐
  │ CHECKPOINT 3: Authentication Level (Auth Service)      │
  │ ✓ JWT token verification                               │
  │ ✓ Token expiration check                               │
  │ ✓ Role-based access control (RBAC)                     │
  │ ✓ Brute-force detection                                │
  └───────────────────────────┬────────────────────────────┘
                              │
  ┌───────────────────────────▼────────────────────────────┐
  │ CHECKPOINT 4: Data Level (Payment Service)             │
  │ ✓ Business logic validation                            │
  │ ✓ AES-256-GCM encryption (card data)                   │
  │ ✓ Data masking (response)                              │
  │ ✓ Audit logging                                        │
  └───────────────────────────┬────────────────────────────┘
                              │
  ┌───────────────────────────▼────────────────────────────┐
  │ CHECKPOINT 5: Infrastructure Level (Kubernetes)        │
  │ ✓ Network Policies (Zero Trust)                        │
  │ ✓ Sealed Secrets (credential management)               │
  │ ✓ RBAC (cluster access control)                        │
  │ ✓ Pod Security Standards                               │
  └────────────────────────────────────────────────────────┘
```

## 5. Công Nghệ Sử Dụng (Technology Stack)

### 5.1 Backend

| Công nghệ | Phiên bản | Lý do chọn |
|---|---|---|
| **Node.js** | 20 LTS | Runtime phổ biến, hệ sinh thái npm lớn, async I/O phù hợp microservices |
| **Express.js** | 4.x | Framework web nhẹ, linh hoạt, middleware ecosystem phong phú |
| **PostgreSQL** | 15 | RDBMS mạnh mẽ, hỗ trợ ACID, phù hợp cho dữ liệu tài chính |
| **JWT** | jsonwebtoken | Xác thực stateless, phù hợp kiến trúc microservices |
| **bcrypt** | bcryptjs | Mã hóa mật khẩu một chiều, chống rainbow table attack |

### 5.2 Infrastructure

| Công nghệ | Lý do chọn |
|---|---|
| **Docker** | Container hóa ứng dụng, đảm bảo consistency giữa các môi trường |
| **Kubernetes** | Orchestration, tự động scaling, self-healing, Network Policies |
| **Sealed Secrets** | Mã hóa secrets trong Git repo, an toàn cho GitOps workflow |
| **Trivy** | Scanner mã nguồn mở, hỗ trợ nhiều target (image, filesystem, repo) |

### 5.3 Security Libraries

| Thư viện | Chức năng |
|---|---|
| **Helmet.js** | 15+ HTTP security headers tự động |
| **express-rate-limit** | Chống brute force và DDoS |
| **Joi** | Schema validation cho input |
| **cors** | Cross-Origin Resource Sharing policy |
| **morgan** | HTTP request logging cho audit trail |

## 6. Quyết Định Thiết Kế (Design Decisions)

### Tại sao chọn AES-256-GCM thay vì AES-256-CBC?

| Tiêu chí | AES-256-CBC | AES-256-GCM |
|---|---|---|
| Mã hóa | ✅ Có | ✅ Có |
| Xác thực (Authentication) | ❌ Không | ✅ Có (Auth Tag) |
| Phát hiện tampering | ❌ Không | ✅ Có |
| Hiệu năng | Trung bình | Cao (parallel processing) |
| **Kết luận** | | **✅ Chọn GCM** |

### Tại sao chọn Zero Trust Network thay vì Traditional Perimeter?

- **Traditional**: Tin tưởng tất cả traffic bên trong mạng nội bộ → Nếu attacker vào được 1 pod, có thể tấn công tất cả
- **Zero Trust**: Mặc định không tin ai → Mỗi kết nối phải được xác minh → Attacker vào 1 pod không thể di chuyển sang pod khác (lateral movement prevention)

### Tại sao cần Shift-Left Security?

```
  Chi phí sửa lỗi bảo mật theo giai đoạn:

  $$$$$$$$$    │                                              ████
               │                                         ████
               │                                    ████
               │                               ████
  $$$$         │                          ████
               │                     ████
               │                ████
  $$           │           ████
               │      ████
  $            │ ████
               └──────────────────────────────────────────────
                Code    Build    Test    Deploy    Production

  → Phát hiện lỗ hổng CÀNG SỚM → Chi phí sửa CÀNG THẤP
  → Shift-Left = Đưa kiểm tra bảo mật sang TRÁI (sớm hơn) trong pipeline
```
