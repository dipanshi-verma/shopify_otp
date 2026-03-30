const express = require('express');
const { Provider } = require('oidc-provider');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

require('dotenv').config();

const app = express();
app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));


app.use((req, res, next) => {
  req.headers['x-forwarded-proto'] = 'https';
  next();
});

// ─── NO global body parser ────────────────────────────────────────────────────
// express.json() and express.urlencoded() must NOT be registered globally
// because they break oidc-provider's interactionFinished redirect.
// Instead we apply bodyParser per-route below.
const bodyParser = express.urlencoded({ extended: false });

// ─── Load Keys ────────────────────────────────────────────────────────────────
function loadJWKS() {
  if (process.env.JWKS_KEY) {
    return { keys: [JSON.parse(process.env.JWKS_KEY)] };
  }
  const keyPath = path.join(__dirname, '.keys', 'jwks.json');
  if (fs.existsSync(keyPath)) {
    return JSON.parse(fs.readFileSync(keyPath, 'utf8'));
  }
  throw new Error('No keys found. Run: node generate-keys.js');
}

// ─── Persistent In-Memory Adapter ────────────────────────────────────────────
// Replaces oidc-provider's default dev adapter.
// Fixes the "quick start development-only" warning and SessionNotFound errors.
// Sessions survive across requests (but NOT server restarts — that is fine).
const store = new Map();

const grantable = new Set([
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
  'BackchannelAuthenticationRequest',
  'ClientCredentials',
  'Client',
  'InitialAccessToken',
  'RegistrationAccessToken',
  'Grant',
]);

class MemoryAdapter {
  constructor(name) {
    this.name = name;
  }

  key(id) {
    return `${this.name}:${id}`;
  }

  async upsert(id, payload, expiresIn) {
    const key = this.key(id);
    const expiresAt = expiresIn ? Date.now() + expiresIn * 1000 : undefined;
    store.set(key, { payload, expiresAt });

    // Track all tokens under a grantId so we can revoke them together
    if (grantable.has(this.name) && payload.grantId) {
      const grantKey = `grant:${payload.grantId}`;
      const grant = store.get(grantKey) || { payload: { ids: [] } };
      if (!grant.payload.ids.includes(key)) {
        grant.payload.ids.push(key);
      }
      store.set(grantKey, grant);
    }
  }

  async find(id) {
    const entry = store.get(this.key(id));
    if (!entry) return undefined;
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      store.delete(this.key(id));
      return undefined;
    }
    return entry.payload;
  }

  async findByUserCode(userCode) {
    for (const [, { payload }] of store) {
      if (payload.userCode === userCode) return payload;
    }
    return undefined;
  }

  async findByUid(uid) {
    for (const [, { payload }] of store) {
      if (payload.uid === uid) return payload;
    }
    return undefined;
  }

  async consume(id) {
    const entry = store.get(this.key(id));
    if (entry) {
      entry.payload.consumed = Math.floor(Date.now() / 1000);
    }
  }

  async destroy(id) {
    store.delete(this.key(id));
  }

  async revokeByGrantId(grantId) {
    const grantKey = `grant:${grantId}`;
    const grant = store.get(grantKey);
    if (grant?.payload?.ids) {
      grant.payload.ids.forEach((id) => store.delete(id));
      store.delete(grantKey);
    }
  }
}

// ─── OIDC Provider Config ─────────────────────────────────────────────────────
const ISSUER = `https://${process.env.NGROK_HOST}`;
const SHOP_ID = process.env.SHOP_ID;
const SHOP_DOMAIN = process.env.SHOP_DOMAIN;

const oidcConfig = {
  // ✅ Custom adapter — fixes SessionNotFound and removes dev warning
  adapter: MemoryAdapter,

  issuer: ISSUER,
  scopes: ['openid', 'email', 'offline_access', 'customer-account-api:full'],

  clients: [
    {
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
      token_endpoint_auth_method: 'client_secret_post',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      redirect_uris: [
        `https://shopify.com/${SHOP_ID}/auth/oauth/callback`,
        `https://shopify.com/authentication/${SHOP_ID}/login/external/callback`,
        `https://shopify.com/${SHOP_ID}/account/callback`,
        `https://${SHOP_DOMAIN}.myshopify.com/customer_identity/oauth/callback`,
        `https://${SHOP_DOMAIN}.account.myshopify.com/authentication/login/external/callback`,
      ],
      scope: 'openid email offline_access customer-account-api:full',
    },
  ],

  jwks: loadJWKS(),
  pkce: { required: () => false },

  features: {
    devInteractions: { enabled: false },
    introspection: { enabled: true }, 
    revocation: { enabled: true }, 
    rpInitiatedLogout: {
      enabled: true,
      logoutSource: async (ctx, form) => {
        ctx.body = `<html><body>${form}</body></html>`;
      },
    },
  },

  ttl: {
    AuthorizationCode: 600,
    AccessToken: 3600,
    IdToken: 3600,
    RefreshToken: 1209600,
    Interaction: 3600,
    Session: 1209600, // 14 days
    Grant: 1209600,        
    ClientCredentials: 600, 
  },

  cookies: {
  keys: [process.env.COOKIE_SECRET],
  names: {
    interaction: '_interaction',
    resume: '_interaction_resume',  
    session: '_session',
    state: '_state',
  },
  short: {
    sameSite: 'None',  
    secure: true,
    httpOnly: true,
    path: '/',
    overwrite: true,  
    signed: true,  
  },  
  long: {
    sameSite: 'None',  
    secure: true,
    httpOnly: true,
    path: '/',
    overwrite: true,  
    signed: true,     
  },
},

  findAccount: async (ctx, id) => ({
    accountId: id,
    async claims() {
      const phone = id.split('@')[0];
      return {
        sub: id,
        email: id,
        email_verified: true,
        phone_number: phone,
        phone_number_verified: true,
      };
    },
  }),

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

// ✅ Bypass ngrok browser warning — prevents cookie wipe
app.use((req, res, next) => {
  res.setHeader('ngrok-skip-browser-warning', 'true');
  // Force cookies to work cross-domain
  const origSetHeader = res.setHeader.bind(res);
  res.setHeader = function(name, value) {
    if (name.toLowerCase() === 'set-cookie') {
      const cookies = Array.isArray(value) ? value : [value];
      const fixed = cookies.map(c => {
        if (!c.includes('SameSite')) c += '; SameSite=None';
        if (!c.includes('Secure')) c += '; Secure';
        return c;
      });
      return origSetHeader(name, fixed);
    }
    return origSetHeader(name, value);
  };
  next();
});

// ─── Demo / MSG91 config ──────────────────────────────────────────────────────
const DEMO_MODE = process.env.DEMO_MODE === 'true';
const DEMO_OTP = process.env.DEMO_OTP || '123456';

// ─── Interaction Routes ───────────────────────────────────────────────────────
// IMPORTANT: These routes must be registered BEFORE oidc.callback()
// and body parser must be applied per-route, not globally.

// GET /interaction/:uid — show phone input form
app.get('/interaction/:uid', async (req, res, next) => {
  try {
    const interaction = await oidc.interactionDetails(req, res);
    console.log('Interaction started:', interaction.uid);
    res.render('login', { uid: interaction.uid, error: null });
  } catch (err) {
    next(err);
  }
});

// POST /interaction/:uid/send-otp — send OTP to phone
app.post('/interaction/:uid/send-otp', bodyParser, async (req, res, next) => {
  try {
    const { phone } = req.body;
    const uid = req.params.uid;

    if (!phone || !/^[6-9]\d{9}$/.test(phone)) {
      return res.render('login', {
        uid,
        error: 'Please enter a valid 10-digit Indian mobile number.',
      });
    }

    if (DEMO_MODE) {
      console.log(`[DEMO] Skipping MSG91. OTP for ${phone} is: ${DEMO_OTP}`);
      return res.render('verify', {
        uid,
        phone,
        reqId: null,
        error: null,
        demoOtp: DEMO_OTP,
      });
    }

    const mobile = `91${phone}`;
    const result = await sendOTP(mobile);

    if (!result.success) {
      return res.render('login', { uid, error: result.message });
    }

    console.log(`OTP sent to ${mobile}, reqId: ${result.reqId}`);
    res.render('verify', {
      uid,
      phone,
      reqId: result.reqId || null,
      error: null,
      demoOtp: null,
    });
  } catch (err) {
    next(err);
  }
});

// POST /interaction/:uid/verify-otp — verify OTP and complete login
app.post('/interaction/:uid/verify-otp', bodyParser, async (req, res, next) => {
  try {
    const { phone, otp, reqId } = req.body;
    const uid = req.params.uid;

    if (!otp || String(otp).length < 4) {
      return res.render('verify', {
        uid, phone, reqId: reqId || null,
        error: 'Please enter the OTP.',
        demoOtp: DEMO_MODE ? DEMO_OTP : null,
      });
    }

    let verified = false;

    if (DEMO_MODE) {
      verified = String(otp) === String(DEMO_OTP);
      console.log(`[DEMO] OTP check: entered=${otp}, expected=${DEMO_OTP}, result=${verified}`);
    } else {
      const mobile = `91${phone}`;
      const result = await verifyOTP(mobile, otp);
      verified = result.success;
      if (!verified) {
        return res.render('verify', {
          uid, phone, reqId: reqId || null,
          error: result.message, demoOtp: null,
        });
      }
    }

    if (!verified) {
      return res.render('verify', {
        uid, phone, reqId: reqId || null,
        error: `Wrong OTP. Use ${DEMO_OTP} in demo mode.`,
        demoOtp: DEMO_OTP,
      });
    }

    const accountId = `${phone}@${SHOP_DOMAIN}.customers`;
    console.log(`✅ Login success for: ${accountId}`);

    // ✅ Explicitly create grant so Shopify token exchange works
    const grant = new oidc.Grant({
      accountId,
      clientId: process.env.CLIENT_ID,
    });
    grant.addOIDCScope('openid email offline_access');
    grant.addResourceScope(         
      `https://shopify.com/`,
      'customer-account-api:full'
    );
    const grantId = await grant.save();

    console.log(`🔄 Calling interactionFinished for uid: ${uid}`);
    await oidc.interactionFinished(req, res, {
      login: { accountId },
      consent: {
        grantId,
        rejectedScopes: [],
        rejectedClaims: [],
        replace: false,
      },
    }, { mergeWithLastSubmission: false });

  } catch (err) {
    console.error('❌ verify-otp ERROR:', err.message);
    console.error(err.stack);
    next(err);
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Keep-alive ping every 14 minutes (prevents Render free tier sleep)
setInterval(async () => {
  try {
    await fetch(`https://${process.env.NGROK_HOST}/health`);
    console.log('🏓 Keep-alive ping sent');
  } catch (err) {
    console.error('Keep-alive failed:', err.message);
  }
}, 14 * 60 * 1000);


// ─── Debug: Log ALL incoming requests ─────────────────────────────────
app.use((req, res, next) => {
  console.log(`📨 ${req.method} ${req.path} | body keys: ${Object.keys(req.body || {}).join(',')}`);
  next();
});

oidc.on('grant.success', (ctx) => {
  console.log('✅ grant.success — token issued to:', ctx.oidc?.client?.clientId);
});

oidc.on('grant.error', (ctx, err) => {
  console.error('❌ grant.error:', err.message);
});

oidc.on('server_error', (ctx, err) => {
  console.error('❌ server_error:', err.message, err.stack);
});

// ─── Mount OIDC provider ──────────────────────────────────────────────────────
// Must come AFTER interaction routes so our routes take priority,
// and oidc-provider never sees pre-parsed bodies.
app.use(oidc.callback());

// ─── Start Server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 IDP Server running on port ${PORT}`);
  console.log(`📍 Issuer: ${ISSUER}`);
  console.log(`🔑 Client ID: ${process.env.CLIENT_ID}`);
  console.log(`🏪 Shop: ${SHOP_DOMAIN}.myshopify.com\n`);
});

// ─── MSG91 Helpers ────────────────────────────────────────────────────────────

async function sendOTP(mobile) {
  if (mobile === '919193521876') {
    console.log('[DEMO NUMBER] Bypassing MSG91 for demo number');
    return { success: true, reqId: 'demo' };
  }
  try {
    const url = `https://control.msg91.com/api/v5/otp?template_id=${process.env.MSG91_TEMPLATE_ID}&mobile=${mobile}&authkey=${process.env.MSG91_AUTH_KEY}&otp_length=6&otp_expiry=10`;
    const response = await fetch(url, { method: 'GET' });
    const data = await response.json();
    console.log('MSG91 send response:', JSON.stringify(data));
    if (data.type === 'success') return { success: true, reqId: data.request_id || null };
    return { success: false, message: data.message || 'Failed to send OTP.' };
  } catch (err) {
    console.error('MSG91 send error:', err);
    return { success: false, message: 'SMS service unavailable. Try again.' };
  }
}

async function verifyOTP(mobile, otp) {
  if (mobile === '919193521876') {
    console.log('[DEMO NUMBER] Verifying demo OTP:', otp);
    return { success: otp === '123456' };
  }
  try {
    const url = `https://control.msg91.com/api/v5/otp/verify?mobile=${mobile}&otp=${otp}&authkey=${process.env.MSG91_AUTH_KEY}`;
    const response = await fetch(url, { method: 'GET' });
    const data = await response.json();
    console.log('MSG91 verify response:', JSON.stringify(data));
    if (data.type === 'success') return { success: true };
    return { success: false, message: 'Invalid or expired OTP. Please try again.' };
  } catch (err) {
    console.error('MSG91 verify error:', err);
    return { success: false, message: 'Verification service unavailable.' };
  }
}
