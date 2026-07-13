#!/bin/bash
# =============================================================================
# Kịch bản kiểm thử Network Policies — Zero Trust
# =============================================================================
# Mục đích: Xác minh rằng Kubernetes Network Policies hoạt động đúng
# theo nguyên tắc Zero Trust: "Không tin tưởng bất kỳ ai, xác minh mọi thứ"
#
# Nguyên tắc:
# - Mặc định CHẶN tất cả traffic (deny all)
# - Chỉ cho phép traffic được khai báo rõ ràng (whitelist)
# - Payment Pod chỉ được nói chuyện với PostgreSQL
# - Gateway chỉ được gọi đến Payment và Auth
# - Không ai được truy cập trực tiếp vào database từ bên ngoài
#
# Test cases:
#   TC-01: Payment Pod → PostgreSQL (PHẢI thành công)
#   TC-02: Gateway Pod → Payment Service (PHẢI thành công)
#   TC-03: Random Pod → Payment Service (PHẢI thất bại/timeout)
#   TC-04: Payment Pod → Auth Service (PHẢI thất bại)
#   TC-05: External Pod → PostgreSQL trực tiếp (PHẢI thất bại)
# =============================================================================

set -euo pipefail

# --- Cấu hình ---
NAMESPACE="${K8S_NAMESPACE:-payment-system}"
TIMEOUT="${NETWORK_TIMEOUT:-5}"  # Timeout cho kết nối (giây)

# Màu sắc
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Biến đếm
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# =============================================================================
# Hàm tiện ích
# =============================================================================

print_banner() {
  echo ""
  echo -e "${CYAN}${BOLD}=========================================${NC}"
  echo -e "${CYAN}${BOLD} KIỂM THỬ NETWORK POLICIES${NC}"
  echo -e "${CYAN}${BOLD} Zero Trust Network Segmentation${NC}"
  echo -e "${CYAN}${BOLD}=========================================${NC}"
  echo -e "${YELLOW}Namespace: ${NAMESPACE}${NC}"
  echo -e "${YELLOW}Timeout:   ${TIMEOUT}s${NC}"
  echo -e "${YELLOW}Thời gian: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
  echo ""
}

print_separator() {
  echo -e "${CYAN}-------------------------------------------${NC}"
}

# Kiểm tra kết nối PHẢI THÀNH CÔNG
# @param $1 — Mã test case
# @param $2 — Mô tả
# @param $3 — Pod nguồn (label selector)
# @param $4 — Địa chỉ đích (host:port)
assert_connection_success() {
  local tc_id="$1"
  local description="$2"
  local source_selector="$3"
  local target="$4"

  TOTAL_TESTS=$((TOTAL_TESTS + 1))

  echo -e "${BOLD}${tc_id}: ${description}${NC}"
  echo -e "   Nguồn: ${source_selector}"
  echo -e "   Đích:  ${target}"

  # Lấy tên pod nguồn
  SOURCE_POD=$(kubectl get pods -n "${NAMESPACE}" -l "${source_selector}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

  if [ -z "$SOURCE_POD" ]; then
    FAILED_TESTS=$((FAILED_TESTS + 1))
    echo -e "${RED}❌ [FAIL] ${tc_id}: Không tìm thấy pod với selector '${source_selector}'${NC}"
    echo ""
    return
  fi

  echo -e "   Pod:   ${SOURCE_POD}"

  # Thực hiện kết nối từ pod nguồn đến đích
  RESULT=$(kubectl exec -n "${NAMESPACE}" "${SOURCE_POD}" -- \
    sh -c "nc -zv -w ${TIMEOUT} ${target} 2>&1" 2>/dev/null || echo "FAILED")

  if echo "$RESULT" | grep -qi "open\|succeeded\|connected"; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
    echo -e "${GREEN}✅ [PASS] ${tc_id}: Kết nối THÀNH CÔNG (đúng như mong đợi)${NC}"
  else
    FAILED_TESTS=$((FAILED_TESTS + 1))
    echo -e "${RED}❌ [FAIL] ${tc_id}: Kết nối THẤT BẠI (mong đợi thành công)${NC}"
    echo -e "   ${RED}Chi tiết: ${RESULT}${NC}"
  fi
  echo ""
}

# Kiểm tra kết nối PHẢI THẤT BẠI (bị chặn bởi Network Policy)
# @param $1 — Mã test case
# @param $2 — Mô tả
# @param $3 — Pod nguồn (label selector)
# @param $4 — Địa chỉ đích (host:port)
assert_connection_blocked() {
  local tc_id="$1"
  local description="$2"
  local source_selector="$3"
  local target="$4"

  TOTAL_TESTS=$((TOTAL_TESTS + 1))

  echo -e "${BOLD}${tc_id}: ${description}${NC}"
  echo -e "   Nguồn: ${source_selector}"
  echo -e "   Đích:  ${target}"

  # Lấy tên pod nguồn
  SOURCE_POD=$(kubectl get pods -n "${NAMESPACE}" -l "${source_selector}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

  if [ -z "$SOURCE_POD" ]; then
    FAILED_TESTS=$((FAILED_TESTS + 1))
    echo -e "${RED}❌ [FAIL] ${tc_id}: Không tìm thấy pod với selector '${source_selector}'${NC}"
    echo ""
    return
  fi

  echo -e "   Pod:   ${SOURCE_POD}"

  # Thực hiện kết nối — mong đợi BỊ CHẶN (timeout hoặc refused)
  RESULT=$(kubectl exec -n "${NAMESPACE}" "${SOURCE_POD}" -- \
    sh -c "nc -zv -w ${TIMEOUT} ${target} 2>&1" 2>/dev/null || echo "BLOCKED")

  if echo "$RESULT" | grep -qi "open\|succeeded\|connected"; then
    FAILED_TESTS=$((FAILED_TESTS + 1))
    echo -e "${RED}❌ [FAIL] ${tc_id}: Kết nối THÀNH CÔNG (mong đợi bị chặn!)${NC}"
    echo -e "   ${RED}Network Policy KHÔNG hoạt động!${NC}"
  else
    PASSED_TESTS=$((PASSED_TESTS + 1))
    echo -e "${GREEN}✅ [PASS] ${tc_id}: Kết nối BỊ CHẶN (đúng như mong đợi)${NC}"
    echo -e "   Chi tiết: timeout/refused — Network Policy hoạt động đúng"
  fi
  echo ""
}

print_summary() {
  echo ""
  echo -e "${CYAN}${BOLD}=========================================${NC}"
  echo -e "${CYAN}${BOLD} TỔNG KẾT KIỂM THỬ NETWORK POLICIES${NC}"
  echo -e "${CYAN}${BOLD}=========================================${NC}"
  echo -e " Tổng số test:  ${BOLD}${TOTAL_TESTS}${NC}"
  echo -e " ${GREEN}PASS:          ${PASSED_TESTS}${NC}"
  echo -e " ${RED}FAIL:          ${FAILED_TESTS}${NC}"
  echo -e "${CYAN}=========================================${NC}"

  if [ "$FAILED_TESTS" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}🎉 TẤT CẢ NETWORK POLICIES HOẠT ĐỘNG ĐÚNG!${NC}"
    echo -e "${GREEN}   Zero Trust: Chỉ traffic được phép mới đi qua.${NC}"
  else
    echo -e "${RED}${BOLD}⚠️  CÓ ${FAILED_TESTS} TEST THẤT BẠI!${NC}"
    echo -e "${RED}   Kiểm tra lại Network Policies trong namespace '${NAMESPACE}'.${NC}"
  fi
  echo ""
}

# =============================================================================
# Kiểm tra môi trường
# =============================================================================
check_prerequisites() {
  echo -e "${YELLOW}🔗 Kiểm tra môi trường...${NC}"

  # Kiểm tra kubectl có sẵn
  if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}❌ kubectl chưa được cài đặt!${NC}"
    exit 1
  fi

  # Kiểm tra kết nối đến cluster
  if ! kubectl cluster-info &> /dev/null; then
    echo -e "${RED}❌ Không thể kết nối đến Kubernetes cluster!${NC}"
    exit 1
  fi

  # Kiểm tra namespace tồn tại
  if ! kubectl get namespace "${NAMESPACE}" &> /dev/null; then
    echo -e "${RED}❌ Namespace '${NAMESPACE}' không tồn tại!${NC}"
    exit 1
  fi

  # Hiển thị Network Policies hiện tại
  echo -e "${GREEN}✅ Kết nối cluster thành công${NC}"
  echo ""
  echo -e "${YELLOW}📋 Network Policies trong namespace '${NAMESPACE}':${NC}"
  kubectl get networkpolicies -n "${NAMESPACE}" 2>/dev/null || echo "   (không có)"
  echo ""

  # Tạo pod test tạm thời nếu chưa có (để test TC-03 và TC-05)
  echo -e "${YELLOW}📦 Tạo test pod tạm thời...${NC}"
  kubectl run test-random-pod \
    --image=busybox:1.36 \
    --restart=Never \
    --namespace="${NAMESPACE}" \
    --labels="app=random-test" \
    --command -- sleep 3600 \
    2>/dev/null || echo "   (pod đã tồn tại)"

  # Chờ pod ready
  kubectl wait --for=condition=Ready pod/test-random-pod \
    -n "${NAMESPACE}" --timeout=60s 2>/dev/null || true
  echo ""
}

# =============================================================================
# Dọn dẹp tài nguyên test
# =============================================================================
cleanup() {
  echo -e "${YELLOW}🧹 Dọn dẹp tài nguyên test...${NC}"
  kubectl delete pod test-random-pod -n "${NAMESPACE}" --ignore-not-found=true 2>/dev/null
  echo -e "${GREEN}✅ Dọn dẹp hoàn tất${NC}"
}

# Đảm bảo dọn dẹp khi script kết thúc
trap cleanup EXIT

# =============================================================================
# CHẠY CÁC TEST CASES
# =============================================================================

print_banner
check_prerequisites

# --- TC-01: Payment Pod → PostgreSQL (PHẢI thành công) ---
# Network Policy cho phép payment service kết nối đến database
print_separator
assert_connection_success \
  "TC-01" \
  "Payment Pod → PostgreSQL (port 5432) — PHẢI thành công" \
  "app=payment" \
  "postgres-service 5432"

# --- TC-02: Gateway Pod → Payment Service (PHẢI thành công) ---
# Gateway là entry point, được phép gọi đến Payment Service
print_separator
assert_connection_success \
  "TC-02" \
  "Gateway Pod → Payment Service (port 3002) — PHẢI thành công" \
  "app=gateway" \
  "payment-service 3002"

# --- TC-03: Random Pod → Payment Service (PHẢI thất bại/timeout) ---
# Pod ngẫu nhiên KHÔNG được phép truy cập Payment Service
# Zero Trust: Chỉ Gateway mới được gọi Payment
print_separator
assert_connection_blocked \
  "TC-03" \
  "Random Pod → Payment Service (port 3002) — PHẢI bị chặn" \
  "app=random-test" \
  "payment-service 3002"

# --- TC-04: Payment Pod → Auth Service (PHẢI thất bại) ---
# Payment Service KHÔNG cần gọi Auth Service
# Nguyên tắc Least Privilege: Chỉ cấp quyền tối thiểu cần thiết
print_separator
assert_connection_blocked \
  "TC-04" \
  "Payment Pod → Auth Service (port 3001) — PHẢI bị chặn" \
  "app=payment" \
  "auth-service 3001"

# --- TC-05: External Pod → PostgreSQL trực tiếp (PHẢI thất bại) ---
# KHÔNG pod nào ngoài Payment được truy cập database
# Bảo vệ tầng dữ liệu: Database chỉ nhận kết nối từ Payment Service
print_separator
assert_connection_blocked \
  "TC-05" \
  "External Pod → PostgreSQL trực tiếp (port 5432) — PHẢI bị chặn" \
  "app=random-test" \
  "postgres-service 5432"

# =============================================================================
# Tổng kết
# =============================================================================
print_summary

# Exit code
if [ "$FAILED_TESTS" -gt 0 ]; then
  exit 1
fi
exit 0
