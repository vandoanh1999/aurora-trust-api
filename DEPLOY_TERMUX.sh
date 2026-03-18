#!/data/data/com.termux/files/usr/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║   AURORA TRUST — TERMUX DEPLOYMENT SCRIPT                  ║
# ║   Chạy từng BƯỚC một. Copy-paste từng block vào Termux.    ║
# ╚══════════════════════════════════════════════════════════════╝

# ════════════════════════════════════════════════════════════════
# BƯỚC 0 — Cài đặt Termux lần đầu (chỉ làm một lần)
# ════════════════════════════════════════════════════════════════

# Mở Termux, chạy:
pkg update -y && pkg upgrade -y
pkg install -y git python nodejs openssh
pip install --upgrade pip

# ════════════════════════════════════════════════════════════════
# BƯỚC 1 — Clone repo từ GitHub của bạn
# ════════════════════════════════════════════════════════════════

# Thay YOUR_GITHUB_USERNAME bằng username GitHub của bạn
git clone https://github.com/YOUR_GITHUB_USERNAME/aurora-trust-api.git
cd aurora-trust-api

# ════════════════════════════════════════════════════════════════
# BƯỚC 2 — Cài Railway CLI (công cụ deploy miễn phí)
# ════════════════════════════════════════════════════════════════

npm install -g @railway/cli

# Verify cài thành công:
railway --version
# Phải thấy: @railway/cli@x.x.x

# ════════════════════════════════════════════════════════════════
# BƯỚC 3 — Đăng nhập Railway (mở browser trên điện thoại)
# ════════════════════════════════════════════════════════════════

railway login
# → Sẽ mở browser, đăng nhập GitHub hoặc email
# → Sau khi xong, quay lại Termux

# ════════════════════════════════════════════════════════════════
# BƯỚC 4 — Tạo project trên Railway
# ════════════════════════════════════════════════════════════════

railway init
# → Chọn "Empty Project"
# → Đặt tên: aurora-trust-api

# ════════════════════════════════════════════════════════════════
# BƯỚC 5 — Tạo VC_SIGNING_KEY (bí mật, lưu lại)
# ════════════════════════════════════════════════════════════════

python3 -c "import secrets; print('VC_SIGNING_KEY=' + secrets.token_hex(32))"
# → Copy toàn bộ dòng output. Đây là signing key của bạn. LƯU LẠI.

# ════════════════════════════════════════════════════════════════
# BƯỚC 6 — Set environment variables trên Railway
# (Thay các giá trị bằng giá trị thật của bạn)
# ════════════════════════════════════════════════════════════════

railway variables set VC_SIGNING_KEY="PASTE_KEY_FROM_STEP_5_HERE"
railway variables set BASE_URL="https://YOUR-APP.up.railway.app"
railway variables set DATABASE_PATH="/data/aurora_trust.db"

# Stripe keys (điền sau khi setup Stripe — xem BƯỚC 8):
# railway variables set STRIPE_SECRET_KEY="sk_live_..."
# railway variables set STRIPE_WEBHOOK_SECRET="whsec_..."
# railway variables set STRIPE_PRICE_STARTER="price_..."
# railway variables set STRIPE_PRICE_BUSINESS="price_..."
# railway variables set STRIPE_PRICE_ENTERPRISE="price_..."

# ════════════════════════════════════════════════════════════════
# BƯỚC 7 — Deploy lên Railway
# ════════════════════════════════════════════════════════════════

railway up
# → Railway sẽ detect Dockerfile và build tự động
# → Xem logs: railway logs
# → Lấy URL: railway domain

# Sau khi deploy, test API:
# curl https://YOUR-APP.up.railway.app/health
# → {"status":"ok","version":"1.0.0","timestamp":...}

# ════════════════════════════════════════════════════════════════
# BƯỚC 8 — Setup Stripe (kiếm tiền)
# ════════════════════════════════════════════════════════════════

# 1. Mở https://dashboard.stripe.com trên điện thoại
# 2. Tạo account (miễn phí)
# 3. Vào Products → Add Product, tạo 3 products:
#    - Aurora Trust Starter  → $99/month (recurring)
#    - Aurora Trust Business → $499/month (recurring)
#    - Aurora Trust Enterprise → $1,999/month (recurring)
# 4. Copy Price IDs (dạng price_xxx) vào railway variables (xem BƯỚC 6)
# 5. Vào Developers → Webhooks → Add endpoint:
#    URL: https://YOUR-APP.up.railway.app/billing/webhook
#    Events: checkout.session.completed, customer.subscription.deleted
# 6. Copy webhook signing secret → set STRIPE_WEBHOOK_SECRET

# ════════════════════════════════════════════════════════════════
# BƯỚC 9 — Test toàn bộ flow
# ════════════════════════════════════════════════════════════════

# Đặt URL của bạn:
export API="https://YOUR-APP.up.railway.app"

# 9a. Đăng ký tenant mới (miễn phí):
curl -X POST $API/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test Corp","email":"test@example.com","plan":"starter"}'
# → Nhận api_key: "at_..."

# 9b. Đặt API key:
export KEY="at_PASTE_YOUR_KEY_HERE"

# 9c. Issue một Verifiable Credential:
curl -X POST $API/v1/credentials/issue \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "subject_id": "my-fraud-model-v1",
    "credential_type": "AIModelCompliance",
    "claims": {"risk_level": "high", "validated": true},
    "expires_in_days": 365
  }'

# 9d. Log audit event:
curl -X POST $API/v1/audit/log \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "my-fraud-model-v1",
    "action": "fraud_detection",
    "outcome": "success",
    "metadata": {"transaction_id": "txn-001", "risk_score": 0.12}
  }'

# 9e. Xem audit summary:
curl $API/v1/audit/summary/my-fraud-model-v1 \
  -H "Authorization: Bearer $KEY"

# 9f. Xem landing page:
# Mở browser: https://YOUR-APP.up.railway.app

# ════════════════════════════════════════════════════════════════
# BƯỚC 10 — Setup domain riêng (tùy chọn, $0 với Cloudflare)
# ════════════════════════════════════════════════════════════════

# 1. Mua domain tại Namecheap (~$10/năm) hoặc dùng .dev/.ai
# 2. Vào Railway → Settings → Domains → Add Custom Domain
# 3. Cấu hình CNAME ở Cloudflare trỏ về Railway domain
# 4. Update BASE_URL: railway variables set BASE_URL="https://auroratrust.dev"

# ════════════════════════════════════════════════════════════════
# LỆNH HỮU ÍCH ĐỂ QUẢN LÝ TỪ TERMUX
# ════════════════════════════════════════════════════════════════

# Xem logs realtime:
# railway logs --tail

# Redeploy sau khi sửa code:
# git add . && git commit -m "fix" && git push && railway up

# Xem tất cả variables:
# railway variables

# Check usage/billing Railway:
# railway status

# ════════════════════════════════════════════════════════════════
# CHI PHÍ VẬN HÀNH (THÁNG ĐẦU)
# ════════════════════════════════════════════════════════════════

# Railway Hobby Plan:    $5/tháng (sau free tier $5 credit)
# Domain (tùy chọn):    ~$1/tháng
# Stripe fees:          2.9% + $0.30 mỗi giao dịch
# TỔNG:                 ~$6–8/tháng chi phí vận hành

# Với 5 khách Starter ($99): Revenue = $495/tháng → Profit = ~$487
# Với 5 khách Business ($499): Revenue = $2,495/tháng
# Với 20 khách mix:   Revenue = ~$5,000–$15,000/tháng

echo "Setup hoàn tất. Chạy 'railway up' để deploy."
