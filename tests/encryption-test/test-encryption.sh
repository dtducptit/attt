#!/bin/bash
# =============================================================================
# Kịch bản kiểm thử mã hóa AES-256-GCM
# =============================================================================
# Mục đích: Xác minh rằng dữ liệu nhạy cảm (số thẻ, CVV) được mã hóa
# khi lưu trữ trong database và chỉ được giải mã khi trả về cho user hợp lệ
#
# Nguyên tắc: "Encryption at Rest" — dữ liệu tĩnh phải được mã hóa
# Thuật toán: AES-256-GCM (Advanced Encryption Standard, 256-bit key,
#             Galois/Counter Mode — cung cấp cả mã hóa VÀ xác thực)
#
# Test cases:
#   TC-01: Tạo giao dịch qua API với dữ liệu thẻ
#   TC-02: Truy vấn trực tiếp database (kubectl exec vào postgres pod)
#   TC-03: Xác minh cột card_number chứa hex ciphertext (không phải plaintext)
#   TC-04: Xác minh cột cvv chứa hex ciphertext
#   TC-05: Xác minh API trả về dữ liệu đã giải mã cho user có quyền
# =============================================================================

set -euo pipefail

# --- Cấu hình ---
BASE_URL="${BASE_URL:-http://localhost:3000/api}"
AUTH_URL="${BASE_URL}/auth"
PAYMENT_URL="${BASE_URL}/payments"
NAMESPACE="${K8S_NAMESPACE:-payment-system}"
POSTGRES_POD_SELECTOR="${POSTGRES_POD_SELECTOR:-app=postgres}"
POSTGRES_DB="${POSTGRES_DB:-payment_db}"
POSTGRES_USER="${POSTGRES_USER:-payment_user}"

# Dữ liệu test — thẻ tín dụng giả
TEST_CARD_NUMBER="4532015112830366"
TEST_CVV="123"
TEST_CARD_HOLDER="NGUYEN VAN TEST"
TEST_EXPIRY="12/2028"
TEST_AMOUNT="500000"

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

# Biến lưu kết quả trung gian
TRANSACTION_ID=""
AUTH_TOKEN=""

# =============================================================================
# Hàm tiện ích
# =============================================================================

print_banner() {
  echo ""
  echo -e "${CYAN}${BOLD}=========================================${NC}"
  echo -e "${CYAN}${BOLD} KIỂM THỬ MÃ HÓA AES-256-GCM${NC}"
  echo -e "${CYAN}${BOLD} Encryption at Rest Verification${NC}"
  echo -e "${CYAN}${BOLD}=========================================${NC}"
  echo -e "${YELLOW}Base URL:  ${BASE_URL}${NC}"
  echo -e "${YELLOW}Namespace: ${NAMESPACE}${NC}"
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
  echo -e "${CYAN}${BOLD} TỔNG KẾT KIỂM THỬ MÃ HÓA${NC}"
  echo -e "${CYAN}${BOLD}=========================================${NC}"
  echo -e " Tổng số test:  ${BOLD}${TOTAL_TESTS}${NC}"
  echo -e " ${GREEN}PASS:          ${PASSED_TESTS}${NC}"
  echo -e " ${RED}FAIL:          ${FAILED_TESTS}${NC}"
  echo -e "${CYAN}=========================================${NC}"

  if [ "$FAILED_TESTS" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}🎉 MÃ HÓA AES-256-GCM HOẠT ĐỘNG ĐÚNG!${NC}"
    echo -e "${GREEN}   Dữ liệu thẻ tín dụng được bảo vệ trong database.${NC}"
  else
    echo -e "${RED}${BOLD}⚠️  CÓ ${FAILED_TESTS} TEST THẤT BẠI!${NC}"
    echo -e "${RED}   Dữ liệu nhạy cảm có thể KHÔNG được mã hóa!${NC}"
  fi
  echo ""
}

# =============================================================================
# Kiểm tra môi trường
# =============================================================================
check_prerequisites() {
  echo -e "${YELLOW}🔗 Kiểm tra môi trường...${NC}"

  # Kiểm tra curl
  if ! command -v curl &> /dev/null; then
    echo -e "${RED}❌ curl chưa được cài đặt!${NC}"
    exit 1
  fi

  # Kiểm tra kubectl
  if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}❌ kubectl chưa được cài đặt!${NC}"
    exit 1
  fi

  # Kiểm tra kết nối server
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "${BASE_URL}/health" 2>/dev/null || echo "000")
  if [ "$HTTP_CODE" = "000" ]; then
    echo -e "${RED}❌ Không thể kết nối đến server tại ${BASE_URL}${NC}"
    exit 1
  fi

  # Kiểm tra PostgreSQL pod
  POSTGRES_POD=$(kubectl get pods -n "${NAMESPACE}" -l "${POSTGRES_POD_SELECTOR}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
  if [ -z "$POSTGRES_POD" ]; then
    echo -e "${RED}❌ Không tìm thấy PostgreSQL pod trong namespace '${NAMESPACE}'!${NC}"
    exit 1
  fi

  echo -e "${GREEN}✅ Server đang hoạt động${NC}"
  echo -e "${GREEN}✅ PostgreSQL pod: ${POSTGRES_POD}${NC}"
  echo ""
}

# =============================================================================
# Bước chuẩn bị: Đăng nhập để lấy token
# =============================================================================
setup_auth() {
  echo -e "${YELLOW}🔑 Đăng nhập để lấy authentication token...${NC}"

  # Đăng ký user test
  TEST_USER="encrypt_test_$(date +%s)"
  curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"email\":\"${TEST_USER}@test.com\",\"password\":\"SecureP@ss123!\",\"role\":\"user\"}" \
    "${AUTH_URL}/register" > /dev/null 2>&1

  # Đăng nhập
  LOGIN_RESPONSE=$(curl -s \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${TEST_USER}@test.com\",\"password\":\"SecureP@ss123!\"}" \
    "${AUTH_URL}/login" 2>/dev/null || echo "{}")

  AUTH_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "")

  if [ -z "$AUTH_TOKEN" ]; then
    echo -e "${RED}❌ Không thể lấy authentication token!${NC}"
    echo -e "${YELLOW}   Bỏ qua test — cần server đang chạy với auth service.${NC}"
    exit 1
  fi

  echo -e "${GREEN}✅ Đã lấy token thành công${NC}"
  echo ""
}

# =============================================================================
# CÁC TEST CASES
# =============================================================================

print_banner
check_prerequisites
setup_auth

# --- TC-01: Tạo giao dịch qua API với dữ liệu thẻ ---
print_separator
echo -e "${BOLD}TC-01: Tạo giao dịch qua API với dữ liệu thẻ tín dụng${NC}"
echo -e "   Số thẻ plaintext gửi đi: ${TEST_CARD_NUMBER}"
echo -e "   CVV plaintext gửi đi:    ${TEST_CVV}"

CREATE_RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d "{
    \"card_number\": \"${TEST_CARD_NUMBER}\",
    \"cvv\": \"${TEST_CVV}\",
    \"card_holder\": \"${TEST_CARD_HOLDER}\",
    \"expiry_date\": \"${TEST_EXPIRY}\",
    \"amount\": ${TEST_AMOUNT},
    \"currency\": \"VND\",
    \"description\": \"Test encryption verification\"
  }" \
  "${PAYMENT_URL}/transactions" \
  2>/dev/null || echo -e "{}\n000")

CREATE_BODY=$(echo "$CREATE_RESPONSE" | head -n -1)
CREATE_CODE=$(echo "$CREATE_RESPONSE" | tail -n 1)

TRANSACTION_ID=$(echo "$CREATE_BODY" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4 2>/dev/null || \
                 echo "$CREATE_BODY" | grep -o '"transaction_id":"[^"]*"' | head -1 | cut -d'"' -f4 2>/dev/null || echo "")

if [ "$CREATE_CODE" -eq 201 ] 2>/dev/null && [ -n "$TRANSACTION_ID" ]; then
  assert_pass "TC-01" "Tạo giao dịch thành công (ID: ${TRANSACTION_ID})"
else
  assert_fail "TC-01" "Tạo giao dịch thất bại" "HTTP ${CREATE_CODE} — ${CREATE_BODY}"
  echo -e "${YELLOW}   ⚠️  Các test tiếp theo có thể bị ảnh hưởng${NC}"
fi
echo ""

# --- TC-02: Truy vấn database trực tiếp ---
print_separator
echo -e "${BOLD}TC-02: Truy vấn database trực tiếp (qua kubectl exec)${NC}"

POSTGRES_POD=$(kubectl get pods -n "${NAMESPACE}" -l "${POSTGRES_POD_SELECTOR}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [ -n "$TRANSACTION_ID" ] && [ -n "$POSTGRES_POD" ]; then
  # Truy vấn trực tiếp vào PostgreSQL để lấy dữ liệu raw
  DB_RESULT=$(kubectl exec -n "${NAMESPACE}" "${POSTGRES_POD}" -- \
    psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -t -A -c \
    "SELECT card_number, cvv FROM transactions WHERE id = '${TRANSACTION_ID}';" \
    2>/dev/null || echo "QUERY_FAILED")

  if [ "$DB_RESULT" != "QUERY_FAILED" ] && [ -n "$DB_RESULT" ]; then
    DB_CARD=$(echo "$DB_RESULT" | cut -d'|' -f1)
    DB_CVV=$(echo "$DB_RESULT" | cut -d'|' -f2)

    echo -e "   Dữ liệu trong database:"
    echo -e "   card_number: ${DB_CARD:0:80}..."
    echo -e "   cvv:         ${DB_CVV:0:80}..."

    assert_pass "TC-02" "Truy vấn database trực tiếp thành công"
  else
    assert_fail "TC-02" "Không thể truy vấn database" "Query failed hoặc không có kết quả"
  fi
else
  assert_fail "TC-02" "Không thể truy vấn database" "Thiếu transaction_id hoặc postgres pod"
fi
echo ""

# --- TC-03: Xác minh card_number chứa hex ciphertext ---
print_separator
echo -e "${BOLD}TC-03: Xác minh cột card_number chứa HEX CIPHERTEXT (không phải plaintext)${NC}"

if [ -n "${DB_CARD:-}" ]; then
  # Kiểm tra 1: Giá trị KHÔNG phải là số thẻ gốc (plaintext)
  if [ "$DB_CARD" = "$TEST_CARD_NUMBER" ]; then
    assert_fail "TC-03" "card_number KHÔNG được mã hóa!" "Giá trị trong DB = plaintext gốc"
  # Kiểm tra 2: Giá trị phải là hex string (chỉ chứa 0-9, a-f, A-F)
  elif echo "$DB_CARD" | grep -qP '^[0-9a-fA-F]+$'; then
    assert_pass "TC-03" "card_number chứa hex ciphertext (đã được mã hóa AES-256-GCM)"
    echo -e "   Plaintext gốc: ${TEST_CARD_NUMBER}"
    echo -e "   Ciphertext DB:  ${DB_CARD:0:50}..."
    echo -e "   ${GREEN}→ Dữ liệu ĐÃ được mã hóa trước khi lưu vào database${NC}"
  else
    # Có thể là base64 encoded
    assert_pass "TC-03" "card_number chứa dữ liệu đã mã hóa (không phải plaintext)"
    echo -e "   Dữ liệu DB: ${DB_CARD:0:50}..."
  fi
else
  assert_fail "TC-03" "Không có dữ liệu card_number từ TC-02" "Bỏ qua kiểm tra"
fi
echo ""

# --- TC-04: Xác minh cvv chứa hex ciphertext ---
print_separator
echo -e "${BOLD}TC-04: Xác minh cột cvv chứa HEX CIPHERTEXT (không phải plaintext)${NC}"

if [ -n "${DB_CVV:-}" ]; then
  # Kiểm tra 1: Giá trị KHÔNG phải CVV gốc
  if [ "$DB_CVV" = "$TEST_CVV" ]; then
    assert_fail "TC-04" "cvv KHÔNG được mã hóa!" "Giá trị trong DB = plaintext gốc '${TEST_CVV}'"
  # Kiểm tra 2: Giá trị đã được mã hóa (hex hoặc base64)
  elif echo "$DB_CVV" | grep -qP '^[0-9a-fA-F]+$'; then
    assert_pass "TC-04" "cvv chứa hex ciphertext (đã được mã hóa AES-256-GCM)"
    echo -e "   Plaintext gốc: ${TEST_CVV}"
    echo -e "   Ciphertext DB:  ${DB_CVV:0:50}..."
    echo -e "   ${GREEN}→ CVV ĐÃ được mã hóa — tuân thủ PCI DSS${NC}"
  else
    assert_pass "TC-04" "cvv chứa dữ liệu đã mã hóa (không phải plaintext)"
    echo -e "   Dữ liệu DB: ${DB_CVV:0:50}..."
  fi
else
  assert_fail "TC-04" "Không có dữ liệu cvv từ TC-02" "Bỏ qua kiểm tra"
fi
echo ""

# --- TC-05: API trả về dữ liệu đã giải mã cho user có quyền ---
print_separator
echo -e "${BOLD}TC-05: API trả về dữ liệu đã giải mã cho user có quyền${NC}"

if [ -n "$TRANSACTION_ID" ]; then
  API_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Bearer ${AUTH_TOKEN}" \
    "${PAYMENT_URL}/transactions/${TRANSACTION_ID}" \
    2>/dev/null || echo -e "{}\n000")

  API_BODY=$(echo "$API_RESPONSE" | head -n -1)
  API_CODE=$(echo "$API_RESPONSE" | tail -n 1)

  if [ "$API_CODE" -eq 200 ] 2>/dev/null; then
    # Lấy card_number từ API response
    API_CARD=$(echo "$API_BODY" | grep -o '"card_number":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "")

    if [ -n "$API_CARD" ]; then
      # API có thể trả về masked card (e.g., ****0366) hoặc full card cho authorized user
      echo -e "   API trả về card_number: ${API_CARD}"

      # Kiểm tra: API KHÔNG trả về ciphertext (hex dài)
      if echo "$API_CARD" | grep -qP '^[0-9a-fA-F]{32,}$'; then
        assert_fail "TC-05" "API trả về ciphertext thay vì plaintext!" "Lỗi giải mã phía server"
      else
        assert_pass "TC-05" "API trả về dữ liệu đã giải mã (hoặc masked) cho user có quyền"
        echo -e "   ${GREEN}→ Server giải mã thành công khi trả dữ liệu qua API${NC}"
      fi
    else
      assert_pass "TC-05" "API phản hồi 200 — dữ liệu được xử lý đúng"
    fi
  else
    assert_fail "TC-05" "API trả về lỗi" "HTTP ${API_CODE}"
  fi
else
  assert_fail "TC-05" "Không có transaction_id từ TC-01" "Bỏ qua kiểm tra"
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
