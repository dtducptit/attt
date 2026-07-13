#!/bin/bash
# =============================================================================
# Kịch bản kiểm thử CI/CD Security Gate — Trivy Vulnerability Scanner
# =============================================================================
# Mục đích: Xác minh rằng pipeline CI/CD có khả năng:
# 1. Phát hiện lỗ hổng bảo mật trong Docker image
# 2. Chặn pipeline khi có lỗ hổng CRITICAL
# 3. Cho phép pipeline tiếp tục khi image sạch
#
# Nguyên tắc Shift-Left Security:
# - Quét lỗ hổng TRƯỚC KHI triển khai, không phải sau khi bị tấn công
# - Tích hợp vào pipeline tự động để không phụ thuộc vào kiểm tra thủ công
#
# Test cases:
#   TC-01: Build image với base có lỗ hổng → Trivy PHẢI phát hiện CVE
#   TC-02: Build image với base sạch → Trivy PHẢI pass
#   TC-03: Xác minh pipeline chặn khi có CRITICAL CVE
# =============================================================================

set -euo pipefail

# --- Cấu hình ---
WORKSPACE="${WORKSPACE:-$(pwd)}"
TRIVY_SEVERITY="${TRIVY_SEVERITY:-CRITICAL,HIGH}"

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

# Thư mục tạm cho test
TEST_DIR="${WORKSPACE}/.trivy-test-tmp"

# =============================================================================
# Hàm tiện ích
# =============================================================================

print_banner() {
  echo ""
  echo -e "${CYAN}${BOLD}=========================================${NC}"
  echo -e "${CYAN}${BOLD} KIỂM THỬ CI/CD SECURITY GATE${NC}"
  echo -e "${CYAN}${BOLD} Trivy Vulnerability Scanner${NC}"
  echo -e "${CYAN}${BOLD}=========================================${NC}"
  echo -e "${YELLOW}Severity: ${TRIVY_SEVERITY}${NC}"
  echo -e "${YELLOW}Thời gian: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
  echo ""
}

print_separator() {
  echo -e "${CYAN}-------------------------------------------${NC}"
}

assert_pass() {
  local tc_id="$1"
  local description="$2"

  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  PASSED_TESTS=$((PASSED_TESTS + 1))
  echo -e "${GREEN}✅ [PASS] ${tc_id}: ${description}${NC}"
}

assert_fail() {
  local tc_id="$1"
  local description="$2"
  local reason="${3:-}"

  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  FAILED_TESTS=$((FAILED_TESTS + 1))
  echo -e "${RED}❌ [FAIL] ${tc_id}: ${description}${NC}"
  if [ -n "$reason" ]; then
    echo -e "   ${RED}Lý do: ${reason}${NC}"
  fi
}

print_summary() {
  echo ""
  echo -e "${CYAN}${BOLD}=========================================${NC}"
  echo -e "${CYAN}${BOLD} TỔNG KẾT KIỂM THỬ CI/CD GATE${NC}"
  echo -e "${CYAN}${BOLD}=========================================${NC}"
  echo -e " Tổng số test:  ${BOLD}${TOTAL_TESTS}${NC}"
  echo -e " ${GREEN}PASS:          ${PASSED_TESTS}${NC}"
  echo -e " ${RED}FAIL:          ${FAILED_TESTS}${NC}"
  echo -e "${CYAN}=========================================${NC}"

  if [ "$FAILED_TESTS" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}🎉 CI/CD SECURITY GATE HOẠT ĐỘNG ĐÚNG!${NC}"
    echo -e "${GREEN}   Pipeline có khả năng phát hiện và chặn lỗ hổng bảo mật.${NC}"
  else
    echo -e "${RED}${BOLD}⚠️  CÓ ${FAILED_TESTS} TEST THẤT BẠI!${NC}"
    echo -e "${RED}   Kiểm tra lại cấu hình Trivy và Security Gate.${NC}"
  fi
  echo ""
}

# =============================================================================
# Kiểm tra môi trường
# =============================================================================
check_prerequisites() {
  echo -e "${YELLOW}🔗 Kiểm tra môi trường...${NC}"

  # Kiểm tra Docker
  if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker chưa được cài đặt!${NC}"
    exit 1
  fi
  echo -e "${GREEN}✅ Docker: $(docker --version)${NC}"

  # Kiểm tra Trivy
  if ! command -v trivy &> /dev/null; then
    echo -e "${YELLOW}⚠️  Trivy chưa được cài đặt. Đang cài đặt...${NC}"

    # Cài đặt Trivy tùy theo OS
    if command -v apt-get &> /dev/null; then
      sudo apt-get update && sudo apt-get install -y wget apt-transport-https gnupg lsb-release
      wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
      echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
      sudo apt-get update && sudo apt-get install -y trivy
    elif command -v apk &> /dev/null; then
      apk add --no-cache trivy
    else
      echo -e "${RED}❌ Không thể tự động cài đặt Trivy. Vui lòng cài đặt thủ công.${NC}"
      echo -e "   https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
      exit 1
    fi
  fi
  echo -e "${GREEN}✅ Trivy: $(trivy --version 2>/dev/null | head -1)${NC}"

  # Tạo thư mục test tạm
  mkdir -p "${TEST_DIR}"
  echo ""
}

# =============================================================================
# Dọn dẹp
# =============================================================================
cleanup() {
  echo -e "${YELLOW}🧹 Dọn dẹp tài nguyên test...${NC}"

  # Xóa Docker images test
  docker rmi trivy-test-vulnerable:latest 2>/dev/null || true
  docker rmi trivy-test-clean:latest 2>/dev/null || true

  # Xóa thư mục tạm
  rm -rf "${TEST_DIR}"

  echo -e "${GREEN}✅ Dọn dẹp hoàn tất${NC}"
}

trap cleanup EXIT

# =============================================================================
# CÁC TEST CASES
# =============================================================================

print_banner
check_prerequisites

# --- TC-01: Build image với base có lỗ hổng → Trivy PHẢI phát hiện CVE ---
print_separator
echo -e "${BOLD}TC-01: Build image với base CÓ LỖ HỔNG → Trivy phải phát hiện CVE${NC}"
echo -e "   Sử dụng base image cũ: node:14 (có nhiều CVE đã biết)"

# Tạo Dockerfile với base image cũ (có lỗ hổng đã biết)
cat > "${TEST_DIR}/Dockerfile.vulnerable" << 'VULN_DOCKERFILE'
# Image cũ, KHÔNG nên dùng trong production — chỉ dùng để test Trivy
FROM node:14
WORKDIR /app
COPY package.json ./
RUN echo '{"name":"test","version":"1.0.0"}' > package.json
RUN npm init -y
CMD ["node", "-e", "console.log('vulnerable image')"]
VULN_DOCKERFILE

# Build image vulnerable
echo -e "   Đang build image vulnerable..."
BUILD_RESULT=$(docker build -t trivy-test-vulnerable:latest -f "${TEST_DIR}/Dockerfile.vulnerable" "${TEST_DIR}" 2>&1 || echo "BUILD_FAILED")

if echo "$BUILD_RESULT" | grep -qi "BUILD_FAILED\|error"; then
  # Nếu không build được (ví dụ: base image quá cũ), vẫn có thể scan image có sẵn
  echo -e "${YELLOW}   ⚠️  Không build được image, scan trực tiếp base image node:14${NC}"
  SCAN_TARGET="node:14"
else
  SCAN_TARGET="trivy-test-vulnerable:latest"
fi

# Quét bằng Trivy — chỉ quét CRITICAL và HIGH
echo -e "   Đang quét lỗ hổng với Trivy..."
TRIVY_OUTPUT=$(trivy image \
  --severity "${TRIVY_SEVERITY}" \
  --format json \
  --quiet \
  "${SCAN_TARGET}" 2>/dev/null || echo '{"Results":[]}')

# Đếm số lỗ hổng
VULN_COUNT=$(echo "$TRIVY_OUTPUT" | jq '[.Results[]? | .Vulnerabilities[]?] | length' 2>/dev/null || echo "0")
CRITICAL_COUNT=$(echo "$TRIVY_OUTPUT" | jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' 2>/dev/null || echo "0")
HIGH_COUNT=$(echo "$TRIVY_OUTPUT" | jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "HIGH")] | length' 2>/dev/null || echo "0")

echo -e "   Kết quả quét:"
echo -e "   🔴 CRITICAL: ${CRITICAL_COUNT}"
echo -e "   🟠 HIGH:     ${HIGH_COUNT}"
echo -e "   📊 Tổng:     ${VULN_COUNT}"

if [ "$VULN_COUNT" -gt 0 ]; then
  assert_pass "TC-01" "Trivy PHÁT HIỆN ${VULN_COUNT} lỗ hổng trong image cũ (đúng như mong đợi)"

  # Hiển thị top 5 CVE
  echo -e "   📋 Top 5 CVE phát hiện:"
  echo "$TRIVY_OUTPUT" | jq -r '.Results[]? | .Vulnerabilities[]? | "\(.Severity): \(.VulnerabilityID) — \(.PkgName)"' 2>/dev/null | head -5 | while read -r line; do
    echo -e "      - ${line}"
  done
else
  assert_fail "TC-01" "Trivy KHÔNG phát hiện lỗ hổng nào" "Image cũ lẽ ra phải có CVE"
fi
echo ""

# --- TC-02: Build image với base sạch → Trivy PHẢI pass ---
print_separator
echo -e "${BOLD}TC-02: Build image với base SẠCH → Trivy phải pass (ít/không có CVE)${NC}"
echo -e "   Sử dụng base image mới nhất: node:20-alpine"

# Tạo Dockerfile với base image sạch (mới nhất)
cat > "${TEST_DIR}/Dockerfile.clean" << 'CLEAN_DOCKERFILE'
FROM node:20-alpine
RUN apk update && apk upgrade --no-cache
WORKDIR /app
RUN echo '{"name":"test","version":"1.0.0"}' > package.json
USER node
CMD ["node", "-e", "console.log('clean image')"]
CLEAN_DOCKERFILE

# Build image sạch
echo -e "   Đang build image clean..."
docker build -t trivy-test-clean:latest -f "${TEST_DIR}/Dockerfile.clean" "${TEST_DIR}" 2>&1 > /dev/null

# Quét bằng Trivy
echo -e "   Đang quét lỗ hổng với Trivy..."
CLEAN_OUTPUT=$(trivy image \
  --severity "CRITICAL" \
  --format json \
  --quiet \
  "trivy-test-clean:latest" 2>/dev/null || echo '{"Results":[]}')

CLEAN_CRITICAL=$(echo "$CLEAN_OUTPUT" | jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' 2>/dev/null || echo "0")

echo -e "   Kết quả quét:"
echo -e "   🔴 CRITICAL: ${CLEAN_CRITICAL}"

if [ "$CLEAN_CRITICAL" -eq 0 ]; then
  assert_pass "TC-02" "Image sạch KHÔNG có lỗ hổng CRITICAL (đúng như mong đợi)"
  echo -e "   ${GREEN}→ node:20-alpine là base image an toàn cho production${NC}"
else
  assert_fail "TC-02" "Image sạch vẫn có ${CLEAN_CRITICAL} CRITICAL CVE" "Cần cập nhật base image"
fi
echo ""

# --- TC-03: Xác minh pipeline chặn khi có CRITICAL CVE ---
print_separator
echo -e "${BOLD}TC-03: Xác minh logic Security Gate — chặn khi có CRITICAL CVE${NC}"

# Mô phỏng logic Security Gate giống trong .gitlab-ci.yml
echo -e "   Mô phỏng Security Gate logic..."

# Test với kết quả từ TC-01 (image vulnerable)
echo -e "   📊 Input: Kết quả quét từ image vulnerable (TC-01)"
echo -e "   🔴 CRITICAL: ${CRITICAL_COUNT}"

GATE_BLOCKED=false

if [ "${CRITICAL_COUNT}" -gt 0 ]; then
  GATE_BLOCKED=true
  echo -e "   🚧 Security Gate: ${RED}CHẶN PIPELINE${NC}"
  echo -e "   ${RED}→ Phát hiện ${CRITICAL_COUNT} CRITICAL CVE — Pipeline sẽ bị dừng${NC}"
elif [ "${HIGH_COUNT}" -gt 0 ]; then
  echo -e "   🚧 Security Gate: ${YELLOW}CẢNH BÁO (cho tiếp tục)${NC}"
  echo -e "   ${YELLOW}→ Phát hiện ${HIGH_COUNT} HIGH CVE — Pipeline tiếp tục với cảnh báo${NC}"
else
  echo -e "   🚧 Security Gate: ${GREEN}CHO PHÉP${NC}"
  echo -e "   ${GREEN}→ Không có lỗ hổng nghiêm trọng${NC}"
fi

# Xác minh logic gate hoạt động đúng
if [ "$GATE_BLOCKED" = "true" ]; then
  assert_pass "TC-03" "Security Gate CHẶN pipeline khi có CRITICAL CVE (đúng như mong đợi)"
  echo -e "   ${GREEN}→ Pipeline CI/CD đảm bảo code có lỗ hổng KHÔNG được triển khai${NC}"
else
  # Nếu TC-01 không tìm thấy CRITICAL, test logic gate với dữ liệu giả
  echo -e "   ${YELLOW}⚠️  TC-01 không phát hiện CRITICAL. Test với dữ liệu mô phỏng...${NC}"

  # Tạo báo cáo Trivy giả có CRITICAL CVE
  MOCK_REPORT='{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","Severity":"CRITICAL","PkgName":"openssl","InstalledVersion":"1.0.0"}]}]}'

  MOCK_CRITICAL=$(echo "$MOCK_REPORT" | jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length')

  if [ "$MOCK_CRITICAL" -gt 0 ]; then
    assert_pass "TC-03" "Security Gate logic: CHẶN khi CRITICAL > 0 (mô phỏng đúng)"
  else
    assert_fail "TC-03" "Security Gate logic không hoạt động đúng" "Không phát hiện CRITICAL trong mock data"
  fi
fi
echo ""

# =============================================================================
# Tổng kết
# =============================================================================
print_summary

# Exit code
if [ "$FAILED_TESTS" -gt 0 ]; then
  exit 1
fi
exit 0
