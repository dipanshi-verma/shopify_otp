const express = require('express');
const { Provider } = require('oidc-provider');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

require('dotenv').config();

const app = express();
app.enable('trust proxy');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ─── Load Keys ───────────────────────────────────────────────────────────────
function loadJWKS() {
  if (process.env.PRIVATE_KEY && process.env.PUBLIC_KEY) {
    const { generateKeyPairSync } = require('crypto');
    // Use env-based keys for production
    return { keys: [JSON.parse(process.env.JWKS_KEY)] };
  }
  const keyPath = path.join(__dirname, '.keys', 'jwks.json');
  if (fs.existsSync(keyPath)) {
    return JSON.parse(fs.readFileSync(keyPath, 'utf8'));
  }
  throw new Error('No keys found. Run: node generate-keys.js');
}

// ─── OIDC Provider Config ─────────────────────────────────────────────────────
const ISSUER = `https://${process.env.NGROK_HOST}`;
const SHOP_ID = process.env.SHOP_ID;
const SHOP_DOMAIN = process.env.SHOP_DOMAIN;

// Trust proxy for HTTPS
app.set('trust proxy', true);

const oidcConfig = {
  issuer: ISSUER,
  scopes: ['openid', 'email', 'customer-account-api:full'],

 clients: [
  {
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    token_endpoint_auth_method: 'client_secret_post',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: [
      `https://shopify.com/${SHOP_ID}/auth/oauth/callback`,
      `https://shopify.com/authentication/${SHOP_ID}/login/external/callback`,
      `https://${SHOP_DOMAIN}.myshopify.com/customer_identity/oauth/callback`,
      `https://${SHOP_DOMAIN}.account.myshopify.com/authentication/login/external/callback`,
    ],
    scope: 'openid email customer-account-api:full', 
  },
],
  jwks: loadJWKS(),
  pkce: { required: () => false },
  features: {
    devInteractions: { enabled: false },
  },
  ttl: {
    AuthorizationCode: 600,
    AccessToken: 3600,
    IdToken: 3600,
  },
  cookies: {
    keys: [process.env.COOKIE_SECRET || crypto.randomBytes(32).toString('hex')],
  },
  // Map our internal account to OIDC claims
  findAccount: async (ctx, id) => ({
    accountId: id,
    async claims() {
      return {
        sub: id,
        email: id, // id is stored as email (or phone@domain synthetic email)
      };
    },
  }),
  // Custom interaction routing
  interactions: {
    url: async (ctx, interaction) => `/interaction/${interaction.uid}`,
  },
  renderError: async (ctx, out, error) => {
    console.error('OIDC Error:', error);
    ctx.body = `<h2>Authentication Error</h2><pre>${JSON.stringify(out, null, 2)}</pre>`;
  },
};

const oidc = new Provider(ISSUER, oidcConfig);
oidc.proxy = true;

// ─── Interaction Routes ───────────────────────────────────────────────────────

// Show phone input form
app.get('/interaction/:uid', async (req, res, next) => {
  try {
    const interaction = await oidc.interactionDetails(req, res);
    console.log('Interaction started:', interaction.uid);
    res.render('login', {
      uid: interaction.uid,
      error: null,
    });
  } catch (err) {
    next(err);
  }
});

// Step 1: Send OTP via MSG91
app.post('/interaction/:uid/send-otp', async (req, res, next) => {
  try {
    const { phone } = req.body;
    const uid = req.params.uid;

    if (!phone || !/^[6-9]\d{9}$/.test(phone)) {
      return res.render('login', {
        uid,
        error: 'Please enter a valid 10-digit Indian mobile number.',
      });
    }

    const mobile = `91${phone}`;
    const result = await sendOTP(mobile);

    if (!result.success) {
      return res.render('login', { uid, error: result.message });
    }

    console.log(`OTP sent to ${mobile}`);
    res.render('verify', { uid, phone, reqId: result.reqId || null, error: null, demoOtp: null  });
  } catch (err) {
    next(err);
  }
});

// Step 2: Verify OTP and complete login
app.post('/interaction/:uid/verify-otp', async (req, res, next) => {
  try {
    const { phone, otp } = req.body;
    const uid = req.params.uid;

    if (!otp || otp.length < 4) {
      return res.render('verify', { uid, phone, error: 'Please enter the OTP.' });
    }

    const mobile = `91${phone}`;
    const result = await verifyOTP(mobile, otp);

    if (!result.success) {
      return res.render('verify', { uid, phone, error: result.message });
    }

    // OTP verified — build synthetic email as the account ID
    const email = `${phone}@${process.env.SHOP_DOMAIN}.customers`;

    // Complete the OIDC interaction
    await oidc.interactionFinished(req, res, {
      login: { accountId: email },
      consent: { rejectedScopes: [], rejectedClaims: [], replace: false },
    });
  } catch (err) {
    next(err);
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// ─── MSG91 Helpers ────────────────────────────────────────────────────────────

async function sendOTP(mobile) {
  try {
    const response = await fetch(
      `https://control.msg91.com/api/v5/otp?template_id=${process.env.MSG91_TEMPLATE_ID}&mobile=${mobile}&authkey=${process.env.MSG91_AUTH_KEY}&otp_length=6&otp_expiry=10`,
      { method: 'GET' }
    );
    const data = await response.json();
    console.log('MSG91 send response:', data);

    if (data.type === 'success') return { success: true };
    return { success: false, message: data.message || 'Failed to send OTP.' };
  } catch (err) {
    console.error('MSG91 send error:', err);
    return { success: false, message: 'SMS service unavailable. Try again.' };
  }
}

async function verifyOTP(mobile, otp) {
  try {
    const response = await fetch(
      `https://control.msg91.com/api/v5/otp/verify?mobile=${mobile}&otp=${otp}&authkey=${process.env.MSG91_AUTH_KEY}`,
      { method: 'GET' }
    );
    const data = await response.json();
    console.log('MSG91 verify response:', data);

    if (data.type === 'success') return { success: true };
    return { success: false, message: 'Invalid or expired OTP. Please try again.' };
  } catch (err) {
    console.error('MSG91 verify error:', err);
    return { success: false, message: 'Verification service unavailable.' };
  }
}

// ─── Mount OIDC ───────────────────────────────────────────────────────────────
app.use(oidc.callback());

// ─── Start Server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 IDP Server running on port ${PORT}`);
  console.log(`📍 Issuer: ${ISSUER}`);
  console.log(`🔑 Client ID: ${process.env.CLIENT_ID}`);
  console.log(`🏪 Shop: ${SHOP_DOMAIN}.myshopify.com\n`);
});
