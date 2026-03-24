# Shopify OTP IDP — Setup Guide

A phone OTP login system for your Shopify store using MSG91 + OpenID Connect.

---

## What this does

Replaces Shopify's default email/password login with phone number + OTP (SMS via MSG91).
Works on any Shopify plan (no Plus required).

---

## Step 1 — Get your credentials

### From MSG91 (msg91.com)
1. Sign up / log in
2. **Auth Key** → Profile icon (top right) → API Keys → copy your Auth Key
3. **OTP Widget** → Widgets → pick your widget → Widget Settings → copy Widget ID
4. **Template ID** → SendOTP → Templates → your SMS template → copy Template ID

### From Shopify (do this AFTER deploying — Step 4)
- CLIENT_ID and CLIENT_SECRET come from Shopify after you register the IDP

---

## Step 2 — Deploy to Railway (free)

1. Go to https://railway.app and sign up (free tier works)
2. Click **New Project → Deploy from GitHub repo**
3. Push this project to a GitHub repo first:
   ```
   git init
   git add .
   git commit -m "initial"
   gh repo create shopify-otp-idp --public --push
   ```
4. Connect your GitHub repo in Railway
5. Railway auto-detects Node.js and runs `npm start`
6. Go to **Settings → Networking → Generate Domain** — copy your domain
   Example: `shopify-otp-idp.up.railway.app`

---

## Step 3 — Set environment variables in Railway

In Railway → your project → **Variables** tab, add:

| Variable | Value |
|---|---|
| `NGROK_HOST` | your Railway domain (e.g. `shopify-otp-idp.up.railway.app`) |
| `SHOP_ID` | your Shopify store ID (number from Admin → Settings → General) |
| `SHOP_DOMAIN` | `dipanshi-dynamic-dreamz` (your myshopify subdomain) |
| `MSG91_AUTH_KEY` | from MSG91 |
| `MSG91_WIDGET_ID` | from MSG91 |
| `MSG91_TEMPLATE_ID` | from MSG91 |
| `COOKIE_SECRET` | any long random string |
| `CLIENT_ID` | fill after Step 4 |
| `CLIENT_SECRET` | fill after Step 4 |

### Generate keys on Railway
In Railway → your project → **Deploy** tab → open a shell and run:
```
node generate-keys.js
```

---

## Step 4 — Register IDP in Shopify

1. Go to Shopify Admin → **Settings → Customer Accounts → Authentication → Manage**
2. Click **Add identity provider** (or similar button)
3. Enter your IDP details:
   - **Issuer URL**: `https://YOUR-RAILWAY-DOMAIN`
   - **Discovery URL**: `https://YOUR-RAILWAY-DOMAIN/.well-known/openid-configuration`
4. Shopify gives you a **Client ID** and **Client Secret**
5. Go back to Railway Variables and fill in `CLIENT_ID` and `CLIENT_SECRET`
6. Redeploy

---

## Step 5 — Test it

1. Visit your Shopify store
2. Click **Log in**
3. You should be redirected to your IDP's phone input page
4. Enter a valid Indian mobile number (10 digits, no +91)
5. Enter the OTP received via SMS
6. You're logged into Shopify!

---

## Local development (optional)

```bash
npm install
node generate-keys.js
cp .env.example .env
# fill in .env values

# Use ngrok for a public HTTPS URL:
ngrok http 3000
# copy the ngrok domain into NGROK_HOST in .env

node app.js
```

---

## Troubleshooting

| Error | Fix |
|---|---|
| `No keys found` | Run `node generate-keys.js` first |
| `invalid_redirect_uri` | Make sure SHOP_ID and SHOP_DOMAIN are correct in .env |
| `invalid_client` | CLIENT_ID / CLIENT_SECRET don't match Shopify's values |
| OTP not received | Check MSG91_AUTH_KEY and MSG91_TEMPLATE_ID; verify DLT registration |
| `unsupported_response_type` | Clear cookies and try again |

---

## File structure

```
shopify-otp-idp/
├── app.js              ← main server
├── generate-keys.js    ← run once to create JWT keys
├── package.json
├── .env.example        ← copy to .env and fill values
├── .gitignore
├── views/
│   ├── login.ejs       ← phone number input page
│   └── verify.ejs      ← OTP entry page
└── .keys/              ← auto-generated, git-ignored
    ├── private.pem
    ├── public.pem
    └── jwks.json
```
# shopify_otp
