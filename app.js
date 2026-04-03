// ==============================
// IMPORTS
// ==============================
const express = require('express');
const Redis = require('ioredis');
const redis = new Redis(process.env.REDIS_URL);
const { Provider } = require('oidc-provider');
const path = require('path');
const fs = require('fs');

require('dotenv').config();

const app = express();
app.set('trust proxy', true);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ==============================
// FORCE HTTPS
// ==============================
app.use((req, res, next) => {
  req.headers['x-forwarded-proto'] = 'https';
  next();
});

// ==============================
// RETURN URL STORE
// ==============================
const returnUrlStore = new Map();

function saveReturnUrl(uid, url) {
  if (!uid || !url) return;
  returnUrlStore.set(uid, {
    url,
    expiresAt: Date.now() + 10 * 60 * 1000,
  });
  console.log(`[return_to] saved for ${uid}: ${url}`);
}

function consumeReturnUrl(uid) {
  const entry = returnUrlStore.get(uid);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    returnUrlStore.delete(uid);
    return null;
  }
  returnUrlStore.delete(uid);
  return entry.url;
}

// ==============================
// JWKS
// ==============================
function loadJWKS() {
  if (process.env.JWKS_KEY) {
    return { keys: [JSON.parse(process.env.JWKS_KEY)] };
  }
  const keyPath = path.join(__dirname, '.keys', 'jwks.json');
  if (fs.existsSync(keyPath)) {
    return JSON.parse(fs.readFileSync(keyPath, 'utf8'));
  }
  throw new Error('No keys found.');
}

// ==============================
// REDIS ADAPTER
// ==============================
class RedisAdapter {
  constructor(name) { this.name = name; }
  key(id) { return `oidc:${this.name}:${id}`; }

  async upsert(id, payload, expiresIn) {
    const key = this.key(id);
    await redis.set(key, JSON.stringify(payload), 'EX', expiresIn || 3600);
    if (payload.grantId) {
      const grantKey = `oidc:grant:${payload.grantId}`;
      await redis.sadd(grantKey, key);
      await redis.expire(grantKey, expiresIn || 3600);
    }
  }

  async find(id) {
    const data = await redis.get(this.key(id));
    return data ? JSON.parse(data) : undefined;
  }

  async findByUid(uid) {
    const keys = await redis.keys(`oidc:${this.name}:*`);
    for (const key of keys) {
      const data = await redis.get(key);
      if (data) {
        const parsed = JSON.parse(data);
        if (parsed.uid === uid) return parsed;
      }
    }
    return undefined;
  }

  async findByUserCode(userCode) {
    const keys = await redis.keys(`oidc:${this.name}:*`);
    for (const key of keys) {
      const data = await redis.get(key);
      if (data) {
        const parsed = JSON.parse(data);
        if (parsed.userCode === userCode) return parsed;
      }
    }
    return undefined;
  }

  async consume(id) {
    const data = await redis.get(this.key(id));
    if (data) {
      const payload = JSON.parse(data);
      payload.consumed = Math.floor(Date.now() / 1000);
      await redis.set(this.key(id), JSON.stringify(payload), 'KEEPTTL');
    }
  }

  async destroy(id) {
    await redis.del(this.key(id));
  }

  async revokeByGrantId(grantId) {
    const grantKey = `oidc:grant:${grantId}`;
    const keys = await redis.smembers(grantKey);
    await Promise.all(keys.map(k => redis.del(k)));
    await redis.del(grantKey);
  }
}

// ==============================
// CONFIG
// ==============================
const ISSUER = process.env.ISSUER;
const SHOP_ID = process.env.SHOP_ID;
const SHOP_DOMAIN = process.env.SHOP_DOMAIN;

if (!SHOP_ID || !SHOP_DOMAIN) {
  console.error('Missing SHOP config');
  process.exit(1);
}

const SHOPIFY_STORE_URL = `https://${SHOP_DOMAIN}.myshopify.com`;
const DEMO_MODE = process.env.DEMO_MODE === 'true';
const DEMO_OTP = process.env.DEMO_OTP || '123456';

// ==============================
// PHONE → EMAIL LOOKUP
// ==============================
async function lookupEmailByPhone(phone) {
  if (DEMO_MODE) {
    return `${phone}@demo.example.com`;
  }

  const formattedPhone = `+91${phone}`;
  try {
    const response = await fetch(
      `https://${SHOP_DOMAIN}.myshopify.com/admin/api/2024-01/graphql.json`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': process.env.SHOPIFY_ADMIN_API_TOKEN,
        },
        body: JSON.stringify({
          query: `query ($phone: String!) {
            customers(first: 1, query: $phone) {
              edges { node { email } }
            }
          }`,
          variables: { phone: `phone:${formattedPhone}` },
        }),
      }
    );
    const data = await response.json();
    return data?.data?.customers?.edges?.[0]?.node?.email || null;
  } catch (err) {
    console.error('[lookupEmailByPhone] Error:', err.message);
    return null;
  }
}

// ==============================
// OIDC PROVIDER
// ==============================
const oidc = new Provider(ISSUER, {
  adapter: RedisAdapter,

  extraParams: ['return_to'],

  // ✅ FIX 1: cookies.keys set karo
  cookies: {
    keys: [process.env.COOKIE_SECRET],
    short: { sameSite: 'None', secure: true, httpOnly: true },
    long:  { sameSite: 'None', secure: true, httpOnly: true },
  },

  // ✅ FIX 2: devInteractions band karo
  features: {
    devInteractions: { enabled: false },
    revocation:      { enabled: true },
    introspection:   { enabled: true },
  },

  scopes: ['openid', 'email', 'offline_access', 'customer-account-api:full'],

  claims: {
    openid: ['sub'],
    email:  ['email', 'email_verified'],
  },

  clients: [{
    client_id:                  process.env.CLIENT_ID,
    client_secret:              process.env.CLIENT_SECRET,
    token_endpoint_auth_method: 'client_secret_post',
    grant_types:                ['authorization_code', 'refresh_token'],
    response_types:             ['code'],
    redirect_uris: [
      `https://shopify.com/authentication/${SHOP_ID}/login/external/callback`,
      `https://${SHOP_DOMAIN}.account.myshopify.com/authentication/login/external/callback`,
    ],
    scope: 'openid email offline_access customer-account-api:full',
  }],

  jwks: loadJWKS(),

  pkce: { required: () => false },

  ttl: {
    AuthorizationCode: 300,
    AccessToken:       3600,
    IdToken:           3600,
    RefreshToken:      1209600,
    Interaction:       3600,
    Session:           1209600,
    Grant:             1209600,
  },

  findAccount: async (ctx, id) => {
    if (!id || id === 'undefined' || id === 'null') return undefined;
    return {
      accountId: id,
      async claims() {
        return {
          sub:            id,
          email:          id,
          email_verified: true,
          updated_at:     Math.floor(Date.now() / 1000),
        };
      },
    };
  },

  interactions: {
    url: async (ctx, interaction) => `/interaction/${interaction.uid}`,
  },

  renderError: async (ctx, out, error) => {
    console.error('OIDC Error:', error);
    ctx.body = `<h2>Authentication Error</h2><pre>${JSON.stringify(out, null, 2)}</pre>`;
  },
});

oidc.proxy = true;

// ==============================
// LOGGER
// ==============================
app.use((req, res, next) => {
  console.log(`📨 ${req.method} ${req.path}`, req.query);
  next();
});

// ==============================
// INTERACTION GET
// ==============================
app.get('/interaction/:uid', async (req, res, next) => {
  let details;
  try {
    details = await oidc.interactionDetails(req, res);
  } catch (err) {
    console.log('[Interaction GET] Session error — redirecting');
    return res.redirect(SHOPIFY_STORE_URL);
  }

  const { uid, params, prompt, session } = details;
  console.log(`[OIDC] prompt=${prompt.name} uid=${uid}`);

  if (params.return_to) {
    saveReturnUrl(uid, params.return_to);
  }

  // AUTO CONSENT
  if (prompt.name === 'consent') {
    const { Grant } = oidc;

    let grant = session?.grantId
      ? await Grant.find(session.grantId)
      : null;

    if (!grant) {
      grant = new Grant({
        accountId: session?.accountId,
        clientId:  params.client_id,
      });
    }

    const scopeToGrant = params.scope
      ? (params.scope.includes('offline_access')
          ? params.scope
          : `${params.scope} offline_access`)
      : 'openid email offline_access';

    grant.addOIDCScope(scopeToGrant);
    const grantId = await grant.save();
    consumeReturnUrl(uid);

    return oidc.interactionFinished(
      req, res,
      { consent: { grantId } },
      { mergeWithLastSubmission: true }
    );
  }

  // SHOW LOGIN
  res.render('login', { uid, error: null });
});

// ==============================
// SEND OTP
// ==============================
app.post('/interaction/:uid/send-otp', express.urlencoded({ extended: false }), async (req, res, next) => {
  const { phone } = req.body;
  const { uid }   = req.params;

  if (!phone || !/^[6-9]\d{9}$/.test(phone)) {
    return res.render('login', { uid, error: 'Please enter a valid 10-digit Indian mobile number.' });
  }

  if (DEMO_MODE) {
    console.log(`[DEMO] OTP for ${phone}: ${DEMO_OTP}`);
    return res.render('verify', { uid, phone, reqId: null, error: null, demoOtp: DEMO_OTP });
  }

  const result = await sendOTP(`91${phone}`);
  if (!result.success) {
    return res.render('login', { uid, error: result.message });
  }

  res.render('verify', { uid, phone, reqId: result.reqId || null, error: null, demoOtp: null });
});

// ==============================
// VERIFY OTP
// ==============================
app.post('/interaction/:uid/verify-otp', express.urlencoded({ extended: false }), async (req, res, next) => {
  const { phone, otp, reqId } = req.body;
  const { uid } = req.params;

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
    const result = await verifyOTP(`91${phone}`, otp);
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
      error: `Wrong OTP. Demo OTP is ${DEMO_OTP}`,
      demoOtp: DEMO_OTP,
    });
  }

  const email = await lookupEmailByPhone(phone);
  if (!email) {
    return res.render('verify', {
      uid, phone, reqId: reqId || null,
      error: 'No account found for this number. Please contact support.',
      demoOtp: DEMO_MODE ? DEMO_OTP : null,
    });
  }

  console.log(`✅ OTP verified. Logging in as: ${email}`);

  await oidc.interactionFinished(
    req, res,
    { login: { accountId: email, remember: true } },
    { mergeWithLastSubmission: false }
  );
});

// ==============================
// HEALTH CHECK
// ==============================
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// ==============================
// OIDC EVENTS
// ==============================
oidc.on('authorization.success', (ctx) => {
  console.log('✅ authorization.success');
});
oidc.on('authorization.error', (ctx, err) => {
  console.error('❌ authorization.error:', err.message);
});
oidc.on('grant.success', (ctx) => {
  console.log('✅ grant.success — client:', ctx.oidc?.client?.clientId);
});
oidc.on('grant.error', (ctx, err) => {
  console.error('❌ grant.error:', err.message);
});
oidc.on('server_error', (ctx, err) => {
  console.error('❌ server_error:', err.message, err.stack);
});

// ==============================
// MOUNT OIDC
// ==============================
app.use(oidc.callback());

// ==============================
// ERROR HANDLER
// ==============================
app.use((err, req, res, next) => {
  console.error('[Server Error]', err);
  res.status(err.status || 500).json({
    error: err.error || 'server_error',
    error_description: err.error_description || err.message,
  });
});

// ==============================
// START
// ==============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 IDP Server running on port ${PORT}`);
  console.log(`📍 Issuer: ${ISSUER}`);
  console.log(`🔑 Client ID: ${process.env.CLIENT_ID}`);
  console.log(`🏪 Shop: ${SHOP_DOMAIN}.myshopify.com\n`);
});

// ==============================
// MSG91 HELPERS
// ==============================
async function sendOTP(mobile) {
  try {
    const url =
      `https://control.msg91.com/api/v5/otp` +
      `?template_id=${process.env.MSG91_TEMPLATE_ID}` +
      `&mobile=${mobile}` +
      `&authkey=${process.env.MSG91_AUTH_KEY}` +
      `&otp_length=6&otp_expiry=10`;
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
  try {
    const url =
      `https://control.msg91.com/api/v5/otp/verify` +
      `?mobile=${mobile}&otp=${otp}&authkey=${process.env.MSG91_AUTH_KEY}`;
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