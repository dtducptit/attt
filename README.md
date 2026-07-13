# 🔐 Hệ Thống Thanh Toán Microservice Bảo Mật Đa Tầng

## Multi-layer Security Microservice Payment System

> Bài tập lớn môn **An Toàn Thông Tin** — Ứng dụng bảo mật đa tầng trên nền tảng Kubernetes với CI/CD tích hợp quét lỗ hổng tự động.

---

## 📋 Mục Lục

- [Tổng quan](#tổng-quan)
- [Kiến trúc hệ thống](#kiến-trúc-hệ-thống)
- [Yêu cầu hệ thống](#yêu-cầu-hệ-thống)
- [Hướng dẫn cài đặt nhanh](#hướng-dẫn-cài-đặt-nhanh)
- [Cấu trúc dự án](#cấu-trúc-dự-án)
- [Chạy kiểm thử](#chạy-kiểm-thử)
- [Các tính năng bảo mật](#các-tính-năng-bảo-mật)
- [Tài liệu tham khảo](#tài-liệu-tham-khảo)
- [Tác giả](#tác-giả)

---

## Tổng Quan

Hệ thống thanh toán được xây dựng theo kiến trúc **microservices**, triển khai trên **Kubernetes**, tích hợp **3 tầng bảo mật** từ mã nguồn đến hạ tầng:

1. **Tầng 1 — Application Security**: JWT Authentication, AES-256-GCM Encryption, OWASP Top 10 Mitigation
2. **Tầng 2 — Infrastructure Security**: Kubernetes Network Policies (Zero Trust), RBAC, Sealed Secrets
3. **Tầng 3 — DevSecOps**: Trivy Vulnerability Scanner, Shift-Left Security, CI/CD Security Gates

---

## Kiến Trúc Hệ Thống

```
┌─────────────────────────────────────────────────────────────────┐
│                         INTERNET                                │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTPS (TLS 1.3)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    KUBERNETES CLUSTER                            │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │            API GATEWAY (Port 3000)                        │  │
│  │    Rate Limiter │ Helmet.js │ CORS │ Input Validation     │  │
│  └────────┬────────────────────────────────┬─────────────────┘  │
│           │                                │                    │
│  ┌────────▼────────┐            ┌──────────▼──────────────┐    │
│  │  AUTH SERVICE   │            │   PAYMENT SERVICE       │    │
│  │  (Port 3001)    │            │   (Port 3002)           │    │
│  │                 │            │                         │    │
│  │  • JWT Token    │            │  • AES-256-GCM Encrypt  │    │
│  │  • bcrypt Hash  │            │  • Transaction Process  │    │
│  │  • RBAC         │            │  • Input Validation     │    │
│  └─────────────────┘            └──────────┬──────────────┘    │
│                                            │                    │
│                                 ┌──────────▼──────────────┐    │
│                                 │    POSTGRESQL           │    │
│                                 │  (Encrypted at Rest)    │    │
│                                 └─────────────────────────┘    │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  CI/CD: BUILD → TEST → SCAN → GATE → STAGING → PROD     │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Yêu Cầu Hệ Thống

### Phần mềm bắt buộc

| Phần mềm | Phiên bản tối thiểu | Mục đích |
|---|---|---|
| **Docker** | 24.x | Đóng gói container |
| **kubectl** | 1.28+ | Quản lý Kubernetes cluster |
| **Minikube** hoặc **Kind** | Latest | Kubernetes cluster cục bộ |
| **Node.js** | 20 LTS | Runtime cho microservices |
| **npm** | 10.x | Quản lý packages |
| **Trivy** | 0.50+ | Quét lỗ hổng bảo mật |
| **Git** | 2.x | Quản lý mã nguồn |

### Tùy chọn (cho CI/CD)

| Phần mềm | Mục đích |
|---|---|
| **GitLab Runner** | Chạy CI/CD pipeline |
| **kubeseal** | Tạo Sealed Secrets |

---

## Hướng Dẫn Cài Đặt Nhanh

### Bước 1: Clone dự án

```bash
git clone <repository-url>
cd payment-system
```

### Bước 2: Khởi tạo Kubernetes cluster

```bash
# Sử dụng Minikube
minikube start --cpus=4 --memory=8192 --driver=docker

# Hoặc sử dụng Kind
kind create cluster --name payment-system
```

### Bước 3: Build Docker images

```bash
# Build tất cả services
docker build -t gateway:latest -f Dockerfiles/Dockerfile.gateway services/gateway/
docker build -t auth:latest -f Dockerfiles/Dockerfile.auth services/auth/
docker build -t payment:latest -f Dockerfiles/Dockerfile.payment services/payment/

# Nếu dùng Minikube — load images vào cluster
minikube image load gateway:latest
minikube image load auth:latest
minikube image load payment:latest
```

### Bước 4: Triển khai lên Kubernetes

```bash
# Tạo namespace
kubectl create namespace payment-system

# Áp dụng tất cả manifests
kubectl apply -f k8s/secrets/ -n payment-system
kubectl apply -f k8s/configmaps/ -n payment-system
kubectl apply -f k8s/network-policies/ -n payment-system
kubectl apply -f k8s/rbac/ -n payment-system
kubectl apply -f k8s/services/ -n payment-system
kubectl apply -f k8s/deployments/ -n payment-system

# Chờ rollout hoàn tất
kubectl rollout status deployment/gateway -n payment-system
kubectl rollout status deployment/auth -n payment-system
kubectl rollout status deployment/payment -n payment-system
```

### Bước 5: Truy cập hệ thống

```bash
# Port-forward Gateway service
kubectl port-forward service/gateway-service 3000:3000 -n payment-system

# Hệ thống có thể truy cập tại: http://localhost:3000
```

### Bước 6: Kiểm tra hoạt động

```bash
# Health check
curl http://localhost:3000/api/health

# Đăng ký user
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"SecureP@ss123!","role":"user"}'

# Đăng nhập
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecureP@ss123!"}'
```

---

## Cấu Trúc Dự Án

```
ATTT/
├── 📄 README.md                          # Tài liệu hướng dẫn (file này)
│
├── 📁 ci-cd/                             # CI/CD Pipeline
│   └── .gitlab-ci.yml                    # GitLab CI pipeline (6 stages)
│
├── 📁 Dockerfiles/                       # Dockerfiles cho các services
│   ├── Dockerfile.gateway                # API Gateway (port 3000)
│   ├── Dockerfile.auth                   # Auth Service (port 3001)
│   └── Dockerfile.payment               # Payment Service (port 3002)
│
├── 📁 services/                          # Source code các microservices
│   ├── 📁 gateway/                       # API Gateway Service
│   │   ├── src/
│   │   │   ├── server.js                 # Entry point
│   │   │   ├── middleware/               # Security middleware
│   │   │   └── routes/                   # API routes
│   │   └── package.json
│   │
│   ├── 📁 auth/                          # Authentication Service
│   │   ├── src/
│   │   │   ├── server.js
│   │   │   ├── controllers/              # Auth controllers
│   │   │   ├── middleware/               # JWT middleware
│   │   │   └── models/                   # User model
│   │   └── package.json
│   │
│   └── 📁 payment/                       # Payment Service
│       ├── src/
│       │   ├── server.js
│       │   ├── controllers/              # Payment controllers
│       │   ├── utils/
│       │   │   └── encryption.js         # AES-256-GCM module
│       │   └── models/                   # Transaction model
│       └── package.json
│
├── 📁 k8s/                               # Kubernetes manifests
│   ├── 📁 deployments/                   # Deployment configs
│   ├── 📁 services/                      # Service configs
│   ├── 📁 network-policies/              # Zero Trust policies
│   ├── 📁 rbac/                          # Role-Based Access Control
│   ├── 📁 configmaps/                    # Configuration
│   └── 📁 secrets/                       # Sealed Secrets
│
├── 📁 tests/                             # Kịch bản kiểm thử
│   ├── 📁 auth-test/
│   │   └── test-auth.sh                  # 8 TC xác thực & phân quyền
│   ├── 📁 network-test/
│   │   └── test-network.sh               # 5 TC Zero Trust network
│   ├── 📁 encryption-test/
│   │   └── test-encryption.sh            # 5 TC mã hóa AES-256-GCM
│   └── 📁 cicd-test/
│       └── test-trivy.sh                 # 3 TC CI/CD security gate
│
└── 📁 docs/                              # Tài liệu
    ├── architecture.md                   # Kiến trúc hệ thống
    ├── security-layers.md                # Giải thích 3 tầng bảo mật
    └── test-results.md                   # Template kết quả kiểm thử
```

---

## Chạy Kiểm Thử

### 1. Kiểm thử xác thực & phân quyền (8 test cases)

```bash
chmod +x tests/auth-test/test-auth.sh

# Chạy với URL mặc định (http://localhost:3000/api)
./tests/auth-test/test-auth.sh

# Hoặc chỉ định URL khác
BASE_URL=http://192.168.49.2:30000/api ./tests/auth-test/test-auth.sh
```

### 2. Kiểm thử Network Policies — Zero Trust (5 test cases)

```bash
chmod +x tests/network-test/test-network.sh

# Chạy với namespace mặc định (payment-system)
./tests/network-test/test-network.sh

# Hoặc chỉ định namespace khác
K8S_NAMESPACE=payment-staging ./tests/network-test/test-network.sh
```

### 3. Kiểm thử mã hóa AES-256-GCM (5 test cases)

```bash
chmod +x tests/encryption-test/test-encryption.sh

# Chạy test mã hóa
BASE_URL=http://localhost:3000/api ./tests/encryption-test/test-encryption.sh
```

### 4. Kiểm thử CI/CD Security Gate (3 test cases)

```bash
chmod +x tests/cicd-test/test-trivy.sh

# Yêu cầu: Docker và Trivy phải được cài đặt
./tests/cicd-test/test-trivy.sh
```

### 5. Chạy tất cả tests

```bash
# Cấp quyền thực thi cho tất cả scripts
chmod +x tests/**/*.sh

# Chạy lần lượt
./tests/auth-test/test-auth.sh && \
./tests/network-test/test-network.sh && \
./tests/encryption-test/test-encryption.sh && \
./tests/cicd-test/test-trivy.sh

echo "✅ Tất cả kiểm thử hoàn tất!"
```

---

## Các Tính Năng Bảo Mật

### Tóm tắt theo tầng

| Tầng | Tính năng | Công nghệ | Chống lại |
|---|---|---|---|
| **Tầng 1: Application** | Xác thực JWT | jsonwebtoken, bcrypt | Truy cập trái phép |
| | Mã hóa AES-256-GCM | Node.js crypto | Đánh cắp dữ liệu thẻ |
| | Input Validation | Joi | SQL Injection, XSS |
| | HTTP Security Headers | Helmet.js | Clickjacking, MIME sniff |
| | Rate Limiting | express-rate-limit | Brute force, DDoS |
| | CORS Policy | cors | CSRF |
| **Tầng 2: Infrastructure** | Network Policies | Kubernetes | Lateral movement |
| | RBAC | Kubernetes | Privilege escalation |
| | Sealed Secrets | Bitnami | Credential leak |
| | Non-root Containers | Docker | Container escape |
| **Tầng 3: DevSecOps** | Vulnerability Scan | Trivy | Vulnerable dependencies |
| | Security Gate | GitLab CI | Triển khai code có lỗ hổng |
| | Multi-stage Build | Docker | Image quá lớn, attack surface |
| | Manual Approval | GitLab CI | Triển khai không kiểm soát |

### Chi tiết từng tầng

Xem tài liệu chi tiết tại:
- 📖 [Kiến trúc hệ thống](docs/architecture.md)
- 🔐 [Giải thích các tầng bảo mật](docs/security-layers.md)
- 📊 [Kết quả kiểm thử](docs/test-results.md)

---

## Tài Liệu Tham Khảo

1. **OWASP Top 10 (2021)** — Danh sách 10 rủi ro bảo mật ứng dụng web phổ biến nhất. [https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)

2. **NIST Special Publication 800-38D** — Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM). Tiêu chuẩn mã hóa AES-GCM. [https://csrc.nist.gov/publications/detail/sp/800-38d/final](https://csrc.nist.gov/publications/detail/sp/800-38d/final)

3. **Kubernetes Network Policies** — Tài liệu chính thức về Network Policies và Zero Trust trong Kubernetes. [https://kubernetes.io/docs/concepts/services-networking/network-policies/](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

4. **Trivy — Aqua Security** — Comprehensive security scanner for containers, filesystems, Git repositories, and Kubernetes. [https://aquasecurity.github.io/trivy/](https://aquasecurity.github.io/trivy/)

5. **JSON Web Tokens (RFC 7519)** — Tiêu chuẩn Internet cho token xác thực stateless. [https://datatracker.ietf.org/doc/html/rfc7519](https://datatracker.ietf.org/doc/html/rfc7519)

6. **PCI DSS v4.0** — Payment Card Industry Data Security Standard — Tiêu chuẩn bảo mật dữ liệu thẻ thanh toán. [https://www.pcisecuritystandards.org/](https://www.pcisecuritystandards.org/)

7. **Bitnami Sealed Secrets** — Kubernetes controller và công cụ mã hóa Secrets an toàn cho GitOps. [https://sealed-secrets.netlify.app/](https://sealed-secrets.netlify.app/)

8. **Docker Security Best Practices** — Hướng dẫn bảo mật Docker container từ Docker Inc. [https://docs.docker.com/develop/security-best-practices/](https://docs.docker.com/develop/security-best-practices/)

---

## Tác Giả

| Họ và tên | Vai trò |
|---|---|
| **Khuất Minh Hoàng** | Phát triển & Kiến trúc hệ thống |
| **Đỗ Trọng Đức** | Bảo mật & DevSecOps |

---

## Giấy Phép

Dự án này được phát triển cho mục đích học tập trong môn An Toàn Thông Tin.

---

<p align="center">
  <b>🔐 Defense in Depth — Bảo mật không phải đích đến, mà là hành trình 🔐</b>
</p>
