#!/bin/bash
# =============================================================================
# Kịch bản kiểm thử xác thực và phân quyền (Authentication & Authorization)
# =============================================================================
# Mục đích: Kiểm tra toàn bộ luồng xác thực JWT và phân quyền RBAC
# Bao gồm 8 test cases kiểm tra các kịch bản:
#   - Không có token, token hết hạn, token không hợp lệ
#   - Sai role, đăng ký, đăng nhập, sai mật khẩu
# Kết quả: Hiển thị màu (xanh=PASS, đỏ=FAIL) và tổng kết cuối
# =============================================================================

set -euo pipefail

# --- Cấu hình ---
# Base URL có thể cấu hình qua biến môi trường
BASE_URL="${BASE_URL:-http://localhost:3000/api}"
AUTH_URL="${BASE_URL}/auth"

# Màu sắc cho output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color — reset màu

# Biến đếm kết quả
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Dữ liệu test — tạo user ngẫu nhiên để tránh conflict
TEST_USER="testuser_$(date +%s)"
TEST_EMAIL="${TEST_USER}@test.com"
TEST_PASSWORD="SecureP@ss123!"

# Token mẫu — các token test cố định
EXPIRED_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjIzOTAyM30.4Adcj3UFYzPUVaVF43FmMab6RlaQD8A9V8wFzzhtSUo"
INVALID_TOKEN="invalid.token.here"
VALID_TOKEN=""  # Sẽ lấy sau khi login thành công

# =============================================================================
# Hàm tiện ích
# =============================================================================

/**
 * In banner tiêu đề
 */
print_banner() {
  echo ""
  echo -e "${CYAN}${BOLD}=========================================${NC}"
  echo -e "${CYAN}${BOLD} KIỂM THỬ XÁC THỰC VÀ PHÂN QUYỀN${NC}"
  echo -e "${CYAN}${BOLD} Authentication & Authorization Tests${NC}"
  echo -e "${CYAN}${BOLD}=========================================${NC}"
  echo -e "${YELLOW}Base URL: ${BASE_URL}${NC}"
  echo -e "${YELLOW}Thời gian: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
  echo ""
}

/**
 * Ghi kết quả test case
 * @param {string} $1 — Mã test case (VD: TC-01)
 * @param {string} $2 — Mô tả test case
 * @param {int}    $3 — HTTP status code thực tế
 * @param {int}    $4 — HTTP status code mong đợi
 */
assert_status() {
  local tc_id="$1"
  local description="$2"
  local actual="$3"
  local expected="$4"

  TOTAL_TESTS=$((TOTAL_TESTS + 1))

  if [ "$actual" -eq "$expected" ] 2>/dev/null; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
    echo -e "${GREEN}✅ [PASS] ${tc_id}: ${description}${NC}"
    echo -e "   Mong đợi: ${expected} | Thực tế: ${actual}"
  else
    FAILED_TESTS=$((FAILED_TESTS + 1))
    echo -e "${RED}❌ [FAIL] ${tc_id}: ${description}${NC}"
    echo -e "   ${RED}Mong đợi: ${expected} | Thực tế: ${actual}${NC}"
  fi
  echo ""
}

/**
 * In dấu phân cách
 */
print_separator() {
  echo -e "${CYAN}-------------------------------------------${NC}"
}

/**
 * In tổng kết kiểm thử
 */
print_summary() {
  echo ""
  echo -e "${CYAN}${BOLD}=========================================${NC}"
  echo -e "${CYAN}${BOLD} TỔNG KẾT KIỂM THỬ XÁC THỰC${NC}"
  echo -e "${CYAN}${BOLD}=========================================${NC}"
  echo -e " Tổng số test:  ${BOLD}${TOTAL_TESTS}${NC}"
  echo -e " ${GREEN}PASS:          ${PASSED_TESTS}${NC}"
  echo -e " ${RED}FAIL:          ${FAILED_TESTS}${NC}"
  echo -e "${CYAN}=========================================${NC}"

  if [ "$FAILED_TESTS" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}🎉 TẤT CẢ CÁC TEST ĐỀU PASS!${NC}"
  else
    echo -e "${RED}${BOLD}⚠️  CÓ ${FAILED_TESTS} TEST THẤT BẠI!${NC}"
  fi
  echo ""
}

# =============================================================================
# Kiểm tra kết nối đến server
# =============================================================================
check_server() {
  echo -e "${YELLOW}🔗 Kiểm tra kết nối đến server...${NC}"
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "${BASE_URL}/health" 2>/dev/null || echo "000")

  if [ "$HTTP_CODE" = "000" ]; then
    echo -e "${RED}❌ Không thể kết nối đến server tại ${BASE_URL}${NC}"
    echo -e "${YELLOW}   Đảm bảo server đang chạy và URL đúng.${NC}"
    echo -e "${YELLOW}   Sử dụng: BASE_URL=http://your-server:port/api $0${NC}"
    exit 1
  fi

  echo -e "${GREEN}✅ Server đang hoạt động (HTTP ${HTTP_CODE})${NC}"
  echo ""
}

# =============================================================================
# CÁC TEST CASES
# =============================================================================

print_banner
check_server

# --- TC-01: Request không có token → mong đợi 401 Unauthorized ---
print_separator
echo -e "${BOLD}TC-01: Request không có token → mong đợi 401${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "${BASE_URL}/payments" \
  2>/dev/null || echo "000")
assert_status "TC-01" "Request không có token → 401 Unauthorized" "$HTTP_CODE" "401"

# --- TC-02: Request với token đã hết hạn → mong đợi 401 ---
print_separator
echo -e "${BOLD}TC-02: Request với token hết hạn → mong đợi 401${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${EXPIRED_TOKEN}" \
  "${BASE_URL}/payments" \
  2>/dev/null || echo "000")
assert_status "TC-02" "Request với token hết hạn → 401 Unauthorized" "$HTTP_CODE" "401"

# --- TC-03: Request với token không hợp lệ → mong đợi 403 ---
print_separator
echo -e "${BOLD}TC-03: Request với token không hợp lệ → mong đợi 403${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${INVALID_TOKEN}" \
  "${BASE_URL}/payments" \
  2>/dev/null || echo "000")
assert_status "TC-03" "Request với token không hợp lệ → 403 Forbidden" "$HTTP_CODE" "403"

# --- TC-04: Request với sai role → mong đợi 403 ---
# Tạo token cho user thường, truy cập admin endpoint
print_separator
echo -e "${BOLD}TC-04: Request với sai role (user truy cập admin) → mong đợi 403${NC}"
# Đầu tiên đăng ký và login để lấy user token
REGISTER_RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${TEST_USER}_role\",\"email\":\"role_${TEST_EMAIL}\",\"password\":\"${TEST_PASSWORD}\",\"role\":\"user\"}" \
  "${AUTH_URL}/register" \
  2>/dev/null || echo -e "\n000")
REGISTER_BODY=$(echo "$REGISTER_RESPONSE" | head -n -1)
REGISTER_CODE=$(echo "$REGISTER_RESPONSE" | tail -n 1)

LOGIN_RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"role_${TEST_EMAIL}\",\"password\":\"${TEST_PASSWORD}\"}" \
  "${AUTH_URL}/login" \
  2>/dev/null || echo -e "\n000")
LOGIN_BODY=$(echo "$LOGIN_RESPONSE" | head -n -1)
USER_TOKEN=$(echo "$LOGIN_BODY" | grep -o '"token":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "")

if [ -n "$USER_TOKEN" ]; then
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/admin/users" \
    2>/dev/null || echo "000")
  assert_status "TC-04" "User role truy cập admin endpoint → 403 Forbidden" "$HTTP_CODE" "403"
else
  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  FAILED_TESTS=$((FAILED_TESTS + 1))
  echo -e "${RED}❌ [FAIL] TC-04: Không thể lấy user token để test role${NC}"
  echo ""
fi

# --- TC-05: Request với token hợp lệ → mong đợi 200 ---
print_separator
echo -e "${BOLD}TC-05: Request với token hợp lệ → mong đợi 200${NC}"

# Đăng ký user mới
REGISTER_RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${TEST_USER}\",\"email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASSWORD}\",\"role\":\"user\"}" \
  "${AUTH_URL}/register" \
  2>/dev/null || echo -e "\n000")

# Login để lấy token
LOGIN_RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASSWORD}\"}" \
  "${AUTH_URL}/login" \
  2>/dev/null || echo -e "\n000")
LOGIN_BODY=$(echo "$LOGIN_RESPONSE" | head -n -1)
VALID_TOKEN=$(echo "$LOGIN_BODY" | grep -o '"token":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "")

if [ -n "$VALID_TOKEN" ]; then
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${VALID_TOKEN}" \
    "${BASE_URL}/payments" \
    2>/dev/null || echo "000")
  assert_status "TC-05" "Request với token hợp lệ → 200 OK" "$HTTP_CODE" "200"
else
  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  FAILED_TESTS=$((FAILED_TESTS + 1))
  echo -e "${RED}❌ [FAIL] TC-05: Không thể lấy valid token${NC}"
  echo ""
fi

# --- TC-06: Đăng ký user mới → mong đợi 201 ---
print_separator
echo -e "${BOLD}TC-06: Đăng ký user mới → mong đợi 201${NC}"
NEW_USER="newuser_$(date +%s)"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${NEW_USER}\",\"email\":\"${NEW_USER}@test.com\",\"password\":\"${TEST_PASSWORD}\",\"role\":\"user\"}" \
  "${AUTH_URL}/register" \
  2>/dev/null || echo "000")
assert_status "TC-06" "Đăng ký user mới → 201 Created" "$HTTP_CODE" "201"

# --- TC-07: Đăng nhập đúng thông tin → mong đợi 200 + JWT ---
print_separator
echo -e "${BOLD}TC-07: Đăng nhập đúng thông tin → mong đợi 200 + JWT token${NC}"
LOGIN_RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${NEW_USER}@test.com\",\"password\":\"${TEST_PASSWORD}\"}" \
  "${AUTH_URL}/login" \
  2>/dev/null || echo -e "\n000")
LOGIN_BODY=$(echo "$LOGIN_RESPONSE" | head -n -1)
LOGIN_CODE=$(echo "$LOGIN_RESPONSE" | tail -n 1)

# Kiểm tra cả status code VÀ sự tồn tại của token trong response
JWT_TOKEN=$(echo "$LOGIN_BODY" | grep -o '"token":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "")

TOTAL_TESTS=$((TOTAL_TESTS + 1))
if [ "$LOGIN_CODE" -eq 200 ] 2>/dev/null && [ -n "$JWT_TOKEN" ]; then
  PASSED_TESTS=$((PASSED_TESTS + 1))
  echo -e "${GREEN}✅ [PASS] TC-07: Đăng nhập thành công → 200 + JWT token${NC}"
  echo -e "   HTTP Status: ${LOGIN_CODE}"
  echo -e "   JWT Token: ${JWT_TOKEN:0:50}..."
else
  FAILED_TESTS=$((FAILED_TESTS + 1))
  echo -e "${RED}❌ [FAIL] TC-07: Đăng nhập thất bại${NC}"
  echo -e "   ${RED}HTTP Status: ${LOGIN_CODE} | Token: ${JWT_TOKEN:-'không có'}${NC}"
fi
echo ""

# --- TC-08: Đăng nhập sai mật khẩu → mong đợi 401 ---
print_separator
echo -e "${BOLD}TC-08: Đăng nhập sai mật khẩu → mong đợi 401${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${NEW_USER}@test.com\",\"password\":\"WrongPassword123!\"}" \
  "${AUTH_URL}/login" \
  2>/dev/null || echo "000")
assert_status "TC-08" "Đăng nhập sai mật khẩu → 401 Unauthorized" "$HTTP_CODE" "401"

# =============================================================================
# Tổng kết
# =============================================================================
print_summary

# Exit code dựa trên kết quả test
if [ "$FAILED_TESTS" -gt 0 ]; then
  exit 1
fi
exit 0
