# Các Tầng Bảo Mật Trong Hệ Thống (Security Layers)

## Tổng Quan

Hệ thống thanh toán microservice áp dụng mô hình **Defense in Depth** (Phòng thủ theo chiều sâu) với **3 tầng bảo mật** chồng lấp lên nhau. Nếu một tầng bị xuyên thủng, các tầng còn lại vẫn bảo vệ hệ thống.

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   ┌─────────────────────────────────────────────────┐   │
│   │                                                 │   │
│   │   ┌─────────────────────────────────────────┐   │   │
│   │   │                                         │   │   │
│   │   │         DỮ LIỆU & ỨNG DỤNG             │   │   │
│   │   │      (Cần được bảo vệ)                  │   │   │
│   │   │                                         │   │   │
│   │   └─────────────────────────────────────────┘   │   │
│   │                                                 │   │
│   │      TẦNG 1: Application Security               │   │
│   │      (JWT, AES-256-GCM, OWASP)                  │   │
│   │                                                 │   │
│   └─────────────────────────────────────────────────┘   │
│                                                         │
│      TẦNG 2: Infrastructure Security                    │
│      (Network Policies, RBAC, Sealed Secrets)           │
│                                                         │
└─────────────────────────────────────────────────────────┘

   TẦNG 3: DevSecOps
   (Trivy, Shift-Left, CI/CD Security Gates)
```

---

## Tầng 1: Application Security (Bảo Mật Tầng Ứng Dụng)

### Mục đích
Bảo vệ ứng dụng khỏi các cuộc tấn công phổ biến theo danh sách OWASP Top 10, đảm bảo xác thực/phân quyền đúng đắn, và mã hóa dữ liệu nhạy cảm.

### 1.1 JWT Authentication (Xác thực bằng JSON Web Token)

**Cơ chế hoạt động**:
```
  ┌────────────┐        ┌────────────┐        ┌────────────┐
  │   Client   │        │   Auth     │        │  Payment   │
  │            │        │  Service   │        │  Service   │
  └─────┬──────┘        └─────┬──────┘        └─────┬──────┘
        │                     │                      │
        │  POST /auth/login   │                      │
        │  {email, password}  │                      │
        │────────────────────>│                      │
        │                     │                      │
        │  200 {token: JWT}   │                      │
        │<────────────────────│                      │
        │                     │                      │
        │  GET /payments      │                      │
        │  Authorization:     │                      │
        │  Bearer <JWT>       │                      │
        │─────────────────────────────────────────-->│
        │                     │                      │
        │                     │  Verify JWT          │
        │                     │<─────────────────────│
        │                     │  Valid ✓             │
        │                     │─────────────────────>│
        │                     │                      │
        │  200 {data}         │                      │
        │<─────────────────────────────────────────── │
```

**Cấu hình JWT**:
| Tham số | Giá trị | Giải thích |
|---|---|---|
| Algorithm | HS256 | HMAC-SHA256, phù hợp cho single-issuer |
| Expiration | 1 giờ | Giảm thời gian token bị lạm dụng nếu bị đánh cắp |
| Secret | 64 bytes random | Đủ dài để chống brute-force |
| Payload | userId, role | Chỉ chứa thông tin cần thiết (Minimal Claims) |

**Tại sao JWT phù hợp cho microservices?**
- **Stateless**: Không cần session store tập trung → mỗi service tự xác thực
- **Scalable**: Thêm service mới chỉ cần share JWT secret
- **Performance**: Không cần query database để verify token

### 1.2 AES-256-GCM Encryption (Mã hóa dữ liệu nhạy cảm)

**Tại sao cần mã hóa tại tầng ứng dụng?**

Ngay cả khi database bị xâm nhập (SQL injection, credential leak), attacker chỉ lấy được **ciphertext** — không đọc được dữ liệu thẻ tín dụng.

**Chi tiết kỹ thuật AES-256-GCM**:

```
                    ┌──────────────────────┐
                    │  ENCRYPTION PROCESS   │
                    └──────────┬───────────┘
                               │
     ┌─────────────────────────┼─────────────────────────┐
     │                         │                         │
     ▼                         ▼                         ▼
┌─────────┐            ┌─────────────┐           ┌──────────┐
│ AES Key │            │     IV      │           │Plaintext │
│ 256-bit │            │  96-bit     │           │ (card #) │
│ (32 B)  │            │ (12 B)     │           │          │
│         │            │ Random mỗi │           │          │
│ Từ      │            │ lần mã hóa │           │          │
│ Sealed  │            │             │           │          │
│ Secret  │            │             │           │          │
└────┬────┘            └──────┬──────┘           └────┬─────┘
     │                        │                       │
     └────────────┬───────────┘───────────────────────┘
                  │
         ┌────────▼────────┐
         │  AES-256-GCM    │
         │  Cipher Engine  │
         └────────┬────────┘
                  │
         ┌────────┴────────┐
         │                 │
    ┌────▼────┐      ┌────▼────┐
    │Ciphertext│     │Auth Tag │
    │(mã hóa) │     │ 128-bit │
    │          │     │ (16 B)  │
    │          │     │ Xác thực│
    │          │     │tính toàn│
    │          │     │ vẹn     │
    └─────────┘     └─────────┘

    Lưu vào DB: iv:authTag:ciphertext (hex format)
```

**Các dữ liệu được mã hóa**:
| Trường | Mã hóa? | Lý do |
|---|---|---|
| card_number | ✅ Có | Thông tin tài chính nhạy cảm (PCI DSS) |
| cvv | ✅ Có | Mã bảo mật thẻ — tuyệt mật |
| card_holder | ❌ Không | Thông tin công khai, cần tìm kiếm |
| amount | ❌ Không | Cần tính toán, aggregate |
| timestamp | ❌ Không | Cần sắp xếp, query |

### 1.3 OWASP Top 10 Mitigation

| OWASP Risk | Biện pháp trong hệ thống |
|---|---|
| A01: Broken Access Control | RBAC + JWT role check tại mỗi endpoint |
| A02: Cryptographic Failures | AES-256-GCM cho dữ liệu nhạy cảm, bcrypt cho mật khẩu |
| A03: Injection | Input validation (Joi), parameterized queries |
| A04: Insecure Design | Security-first architecture, threat modeling |
| A05: Security Misconfiguration | Helmet.js auto-headers, Kubernetes security context |
| A06: Vulnerable Components | Trivy scan trong CI/CD pipeline |
| A07: Auth Failures | Rate limiting, bcrypt, JWT expiration |
| A08: Data Integrity | GCM auth tag, HTTPS only |
| A09: Logging Failures | Morgan request logging, audit trail |
| A10: SSRF | Không cho phép user-controlled URLs |

---

## Tầng 2: Infrastructure Security (Bảo Mật Tầng Hạ Tầng)

### Mục đích
Bảo vệ hệ thống ở cấp độ Kubernetes cluster — kiểm soát ai/cái gì được truy cập tài nguyên nào.

### 2.1 Kubernetes Network Policies (Zero Trust Network)

**Nguyên tắc**: "Không tin tưởng bất kỳ ai" — Mặc định chặn TẤT CẢ traffic, chỉ cho phép những kết nối được khai báo rõ ràng.

```
  TRƯỚC Network Policies (Mặc định Kubernetes):
  ┌──────────────────────────────────────────┐
  │  Tất cả pods nói chuyện được với nhau    │
  │                                          │
  │  Gateway ←→ Auth ←→ Payment ←→ Postgres  │
  │     ↕          ↕         ↕         ↕     │
  │  Random Pod  Random   Random    Random   │
  │                                          │
  │  ⚠️ Attacker vào 1 pod → truy cập TẤT CẢ │
  └──────────────────────────────────────────┘

  SAU Network Policies (Zero Trust):
  ┌──────────────────────────────────────────┐
  │  Chỉ traffic được phép mới đi qua       │
  │                                          │
  │  Gateway ──→ Auth ✅                      │
  │  Gateway ──→ Payment ✅                   │
  │  Payment ──→ Postgres ✅                  │
  │                                          │
  │  Random ──→ Payment ❌ (BLOCKED)         │
  │  Random ──→ Postgres ❌ (BLOCKED)        │
  │  Payment ──→ Auth ❌ (BLOCKED)           │
  │                                          │
  │  ✅ Attacker vào 1 pod → BỊ CÔ LẬP      │
  └──────────────────────────────────────────┘
```

**Danh sách Network Policies**:

| Policy | Ingress (vào) | Egress (ra) | Mục đích |
|---|---|---|---|
| `deny-all` | Chặn tất cả | Chặn tất cả | Baseline — mặc định deny |
| `allow-gateway-ingress` | Từ Ingress Controller | — | Gateway nhận request từ ngoài |
| `allow-gateway-to-services` | — | Đến Auth + Payment | Gateway chuyển tiếp request |
| `allow-payment-to-postgres` | — | Đến PostgreSQL:5432 | Payment truy cập database |
| `allow-postgres-from-payment` | Từ Payment pod | — | Database chỉ nhận từ Payment |

### 2.2 Kubernetes RBAC (Role-Based Access Control)

Kiểm soát ai có quyền làm gì trên Kubernetes cluster.

```
  ┌─────────────────────────────────────────────┐
  │              ServiceAccount                  │
  │  (Mỗi service có ServiceAccount riêng)      │
  ├─────────────────────────────────────────────┤
  │                                             │
  │  gateway-sa:                                │
  │    ✅ Đọc ConfigMap, Secret                 │
  │    ❌ Tạo/xóa Pod                           │
  │    ❌ Truy cập namespace khác               │
  │                                             │
  │  payment-sa:                                │
  │    ✅ Đọc Sealed Secret (encryption key)    │
  │    ✅ Đọc ConfigMap (DB connection)         │
  │    ❌ List pods, services                    │
  │    ❌ Truy cập namespace khác               │
  │                                             │
  │  Nguyên tắc: Mỗi service CHỈ có quyền      │
  │  TỐI THIỂU cần thiết (Least Privilege)      │
  └─────────────────────────────────────────────┘
```

### 2.3 Sealed Secrets (Quản lý bí mật an toàn)

**Vấn đề**: Kubernetes Secrets được encode bằng base64 — BẤT KỲ AI có quyền đọc secrets đều thấy plaintext. Nếu lưu secrets trong Git repo → LỘ thông tin.

**Giải pháp**: Sealed Secrets mã hóa secrets bằng public key — chỉ Sealed Secrets Controller trong cluster mới giải mã được.

```
  ┌─────────────┐     kubeseal     ┌──────────────────┐
  │ Secret YAML │────────────────→│ SealedSecret YAML │
  │ (plaintext) │   (mã hóa)      │ (encrypted)       │
  │             │                  │                   │
  │ DB_PASS:    │                  │ DB_PASS:          │
  │ mypassword  │                  │ AgBy3k...Xy2Q=    │
  └─────────────┘                  └────────┬──────────┘
                                            │
  ⚠️ KHÔNG commit                   ✅ AN TOÀN commit
  vào Git!                          vào Git!
                                            │
                                   ┌────────▼──────────┐
                                   │  K8s Cluster       │
                                   │  Sealed Secrets    │
                                   │  Controller        │
                                   │  (giải mã)         │
                                   └────────┬──────────┘
                                            │
                                   ┌────────▼──────────┐
                                   │  Kubernetes       │
                                   │  Secret (runtime)  │
                                   │  DB_PASS:         │
                                   │  mypassword        │
                                   └───────────────────┘
```

---

## Tầng 3: DevSecOps (Bảo Mật Trong Quy Trình Phát Triển)

### Mục đích
Tích hợp bảo mật vào MỌI giai đoạn của quy trình phát triển phần mềm — từ viết code đến triển khai — theo nguyên tắc **Shift-Left Security**.

### 3.1 Trivy Vulnerability Scanner

**Trivy quét gì?**

```
  ┌──────────────────────────────────────────────────┐
  │                 TRIVY SCANNER                     │
  ├──────────────────────────────────────────────────┤
  │                                                  │
  │  📦 OS Packages                                  │
  │     Alpine APK, Debian/Ubuntu APT, RHEL RPM      │
  │     → Phát hiện CVE trong thư viện hệ thống     │
  │                                                  │
  │  📚 Application Dependencies                     │
  │     npm (package-lock.json), pip, Maven, Go      │
  │     → Phát hiện CVE trong thư viện ứng dụng     │
  │                                                  │
  │  🔧 Configuration                               │
  │     Dockerfile, Kubernetes YAML                  │
  │     → Phát hiện misconfiguration                 │
  │                                                  │
  │  🔑 Secrets                                      │
  │     Hardcoded passwords, API keys                │
  │     → Phát hiện credentials bị lộ               │
  │                                                  │
  └──────────────────────────────────────────────────┘
```

**Phân loại mức độ nghiêm trọng**:

| Mức độ | Mô tả | Hành động |
|---|---|---|
| 🔴 **CRITICAL** | Lỗ hổng có thể bị khai thác ngay, RCE, data breach | **CHẶN pipeline** — không được triển khai |
| 🟠 **HIGH** | Lỗ hổng nghiêm trọng nhưng cần điều kiện để khai thác | **CẢNH BÁO** — cho tiếp tục, sửa trong sprint sau |
| 🟡 **MEDIUM** | Lỗ hổng trung bình | Ghi nhận, lên kế hoạch sửa |
| 🟢 **LOW** | Lỗ hổng nhỏ | Theo dõi |

### 3.2 Shift-Left Security (Dịch chuyển bảo mật sang trái)

```
  Pipeline CI/CD với Shift-Left Security:

  ┌───────┐  ┌───────┐  ┌───────┐  ┌───────┐  ┌─────────┐  ┌────────────┐
  │ BUILD │→│ TEST  │→│ SCAN  │→│ GATE  │→│ STAGING │→│ PRODUCTION │
  │       │  │       │  │       │  │       │  │         │  │            │
  │Docker │  │Unit   │  │Trivy  │  │Phân   │  │kubectl  │  │Manual      │
  │Build  │  │Test   │  │Quét   │  │tích   │  │apply    │  │Approval    │
  │       │  │       │  │CVE    │  │kết quả│  │         │  │            │
  │Multi- │  │Auth   │  │       │  │       │  │Rollout  │  │Rolling     │
  │stage  │  │Crypto │  │JSON   │  │BLOCK  │  │Wait     │  │Update      │
  │Non-   │  │Input  │  │Report │  │if     │  │         │  │            │
  │root   │  │Valid. │  │       │  │CRIT.  │  │         │  │            │
  └───┬───┘  └───┬───┘  └───┬───┘  └───┬───┘  └────┬────┘  └─────┬──────┘
      │          │          │          │            │              │
      ▼          ▼          ▼          ▼            ▼              ▼
   Bảo mật   Bảo mật    Bảo mật   Bảo mật     Bảo mật       Bảo mật
   image     logic      dependency pipeline    deployment    approval
```

**Tại sao Shift-Left quan trọng?**

| Giai đoạn phát hiện lỗi | Chi phí sửa (tương đối) |
|---|---|
| Khi viết code | $1 |
| Khi build | $10 |
| Khi test | $100 |
| Khi staging | $1,000 |
| Khi production | $10,000 |
| Sau khi bị tấn công | $100,000+ |

→ Phát hiện CÀNG SỚM → Chi phí CÀNG THẤP

### 3.3 CI/CD Security Gates

**Quy trình quyết định tại Security Gate**:

```
                    ┌──────────────────┐
                    │  Nhận kết quả    │
                    │  Trivy Scan      │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │ Có CRITICAL CVE? │
                    └────────┬─────────┘
                             │
                   ┌─────────┴─────────┐
                   │                   │
                ┌──▼──┐             ┌──▼──┐
                │ CÓ  │             │KHÔNG│
                └──┬──┘             └──┬──┘
                   │                   │
          ┌────────▼────────┐  ┌───────▼────────┐
          │ ❌ CHẶN PIPELINE│  │ Có HIGH CVE?   │
          │ exit 1          │  └───────┬────────┘
          │                 │          │
          │ Thông báo team  │  ┌───────┴───────┐
          │ Liệt kê CVE    │  │               │
          │ Yêu cầu vá     │  ┌──▼──┐       ┌──▼──┐
          └─────────────────┘  │ CÓ  │       │KHÔNG│
                               └──┬──┘       └──┬──┘
                                  │              │
                         ┌────────▼────────┐  ┌──▼────────────┐
                         │ ⚠️ CẢNH BÁO     │  │ ✅ CHO PHÉP    │
                         │ Cho tiếp tục    │  │ Pipeline sạch  │
                         │ Log cảnh báo    │  │                │
                         │ Sửa sprint sau  │  │                │
                         └─────────────────┘  └────────────────┘
```

---

## Các Tầng Phối Hợp Như Thế Nào?

### Kịch bản 1: Attacker cố gắng SQL Injection

```
  Attacker gửi: ' OR 1=1; DROP TABLE users; --

  Tầng 1 (Application):
    → Gateway: Joi validation CHẶN input không hợp lệ ❌
    → Nếu lọt: Parameterized query ngăn SQL injection ❌
    → Request bị reject TRƯỚC khi đến database

  Tầng 2 (Infrastructure):
    → Network Policy: Attacker không thể truy cập DB trực tiếp ❌
    → RBAC: Không có quyền exec vào pod ❌

  Tầng 3 (DevSecOps):
    → Trivy: Quét npm packages để phát hiện thư viện có lỗ hổng SQL injection
    → Test: Unit test kiểm tra input validation
```

### Kịch bản 2: Attacker lấy được database dump

```
  Attacker có file SQL dump từ PostgreSQL

  Tầng 1 (Application):
    → AES-256-GCM: Dữ liệu thẻ là CIPHERTEXT → không đọc được ✅
    → Cần encryption key (256-bit) để giải mã → brute-force bất khả thi

  Tầng 2 (Infrastructure):
    → Sealed Secrets: Encryption key được mã hóa trong cluster
    → RBAC: Chỉ Payment ServiceAccount mới đọc được secret

  → Kết quả: Attacker chỉ có dữ liệu vô nghĩa (ciphertext)
```

### Kịch bản 3: Supply Chain Attack (thư viện npm bị nhiễm mã độc)

```
  Một npm package bị hacker chèn mã độc

  Tầng 3 (DevSecOps):
    → Trivy: Phát hiện CVE trong package → CHẶN pipeline ❌
    → Security Gate: Không cho triển khai image có lỗ hổng

  Tầng 1 (Application):
    → --ignore-scripts: Dockerfile không chạy postinstall scripts
    → Non-root user: Giới hạn thiệt hại nếu mã độc chạy được

  Tầng 2 (Infrastructure):
    → Network Policy: Pod bị nhiễm không thể kết nối ra ngoài (egress blocked)
    → Container isolated: Không ảnh hưởng đến pods khác
```

---

## Tóm Tắt

| Tầng | Bảo vệ khỏi | Công nghệ | Nguyên tắc |
|---|---|---|---|
| **Tầng 1: Application** | XSS, SQLi, brute force, data theft | JWT, AES-256-GCM, Helmet, Joi | OWASP Top 10 |
| **Tầng 2: Infrastructure** | Lateral movement, privilege escalation, credential leak | Network Policies, RBAC, Sealed Secrets | Zero Trust, Least Privilege |
| **Tầng 3: DevSecOps** | Vulnerable dependencies, supply chain attack | Trivy, CI/CD Gates | Shift-Left Security |

> **Kết luận**: Không có tầng bảo mật nào là đủ một mình. Sức mạnh nằm ở việc **3 tầng phối hợp với nhau** — tạo thành hệ thống phòng thủ nhiều lớp mà attacker phải vượt qua TẤT CẢ để thành công.
