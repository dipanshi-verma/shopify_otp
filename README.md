# Shopify OTP Identity Provider (IDP)

Custom OIDC Identity Provider for Shopify Customer Accounts using MSG91 OTP login.

## Setup

### 1. Install dependencies
```bash
npm install
```

### 2. Generate RSA keys (only needed once)
```bash
node generate-keys.js
```

### 3. Configure environment
```bash
cp .env.example .env
# Edit .env with your actual values
```

### 4. Start ngrok
```bash
ngrok http 3000
# Copy the https URL — paste it as NGROK_HOST in .env (without https://)
```

### 5. Run the server
```bash
npm run dev
```

---

## Critical Rules (do not break these)

1. **COOKIE_SECRET must always be set in .env** — if missing or changed, all sessions break
2. **Never call `oidc.interactionDetails(req, res)` before `interactionFinished`** — it touches `res` and causes "Cannot set headers" error
3. **Never use express-session** — oidc-provider manages its own sessions
4. **Never add global body parser** — use per-route `bodyParser` only
5. **Update NGROK_HOST in .env every time ngrok restarts** (unless you have a fixed domain)

---

## Flow

```
User clicks Login on Shopify
    ↓
Shopify redirects → GET /interaction/:uid  (login.ejs shown)
    ↓
User enters phone → POST /interaction/:uid/send-otp
    ↓
MSG91 sends OTP → verify.ejs shown
    ↓
User enters OTP → POST /interaction/:uid/verify-otp
    ↓
interactionFinished() → redirects back to Shopify callback
    ↓
User is logged in ✅
```

---

## Environment Variables

| Variable | Description |
|---|---|
| `NGROK_HOST` | ngrok hostname without https:// |
| `CLIENT_ID` | Shopify IdP Client ID |
| `CLIENT_SECRET` | Shopify IdP Client Secret |
| `SHOP_ID` | Numeric Shopify Shop ID |
| `SHOP_DOMAIN` | myshopify subdomain |
| `MSG91_AUTH_KEY` | MSG91 API auth key |
| `MSG91_TEMPLATE_ID` | MSG91 OTP SMS template ID |
| `MSG91_WIDGET_ID` | MSG91 Widget ID |
| `COOKIE_SECRET` | Long random string for signing cookies |
| `DEMO_MODE` | `true` to skip real SMS |
| `DEMO_OTP` | OTP to use in demo mode |
