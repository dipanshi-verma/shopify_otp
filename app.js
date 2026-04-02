const express = require('express');
const Redis = require('ioredis');
const redis = new Redis(process.env.REDIS_URL);
const { Provider } = require('oidc-provider');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

require('dotenv').config();

const app = express();
app.set('trust proxy', true);

// //  BODY PARSER 
// app.use(express.json())
// app.use(express.urlencoded({ extended: true }))

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use((req, res, next) => {
  req.headers['x-forwarded-proto'] = 'https';
  next();
});

// const bodyParser = express.urlencoded({ extended: false });

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

// ─── In-Memory Adapter ────────────────────────────────────────────────────────
const store = new Map();

const grantable = new Set([
  'AccessToken', 'AuthorizationCode', 'RefreshToken', 'DeviceCode',
  'BackchannelAuthenticationRequest', 'ClientCredentials', 'Client',
  'InitialAccessToken', 'RegistrationAccessToken', 'Grant',
]);

// class MemoryAdapter {
//   constructor(name) { this.name = name; }

//   key(id) { return `${this.name}:${id}`; }

//   async upsert(id, payload, expiresIn) {
//     const key = this.key(id);
//     const expiresAt = expiresIn ? Date.now() + expiresIn * 1000 : undefined;
//     store.set(key, { payload, expiresAt });
//     if (grantable.has(this.name) && payload.grantId) {
//       const grantKey = `grant:${payload.grantId}`;
//       const grant = store.get(grantKey) || { payload: { ids: [] } };
//       if (!grant.payload.ids.includes(key)) grant.payload.ids.push(key);
//       store.set(grantKey, grant);
//     }
//   }

//   async find(id) {
//     const entry = store.get(this.key(id));
//     if (!entry) return undefined;
//     if (entry.expiresAt && Date.now() > entry.expiresAt) {
//       store.delete(this.key(id));
//       return undefined;
//     }
//     return entry.payload;
//   }

//   async findByUid(uid) {
//     for (const [, entry] of store) {
//       if (entry?.payload?.uid === uid &&
//           (!entry.expiresAt || Date.now() < entry.expiresAt)) {
//         return entry.payload;
//       }
//     }
//     return undefined;
//   }

//   async findByUserCode(userCode) {
//     for (const [, entry] of store) {
//       if (entry?.payload?.userCode === userCode &&
//           (!entry.expiresAt || Date.now() < entry.expiresAt)) {
//         return entry.payload;
//       }
//     }
//     return undefined;
//   }

//   async consume(id) {
//     const entry = store.get(this.key(id));
//     if (entry) entry.payload.consumed = Math.floor(Date.now() / 1000);
//   }

//   async destroy(id) { store.delete(this.key(id)); }

//   async revokeByGrantId(grantId) {
//     const grantKey = `grant:${grantId}`;
//     const grant = store.get(grantKey);
//     if (grant?.payload?.ids) {
//       grant.payload.ids.forEach((id) => store.delete(id));
//       store.delete(grantKey);
//     }
//   }
// }

// REDIS ADAPTER — stores all data in Redis with TTLs, and maintains sets for grantId → token keys for efficient revocation.
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

  async destroy(id) { await redis.del(this.key(id)); }

  async revokeByGrantId(grantId) {
    const grantKey = `oidc:grant:${grantId}`;
    const keys = await redis.smembers(grantKey);
    await Promise.all(keys.map(k => redis.del(k)));
    await redis.del(grantKey);
  }
}
// ─── Config ───────────────────────────────────────────────────────────────────
// const ISSUER      = `https://${process.env.NGROK_HOST}`;
const ISSUER = process.env.ISSUER;
const SHOP_ID = process.env.SHOP_ID;
const SHOP_DOMAIN = process.env.SHOP_DOMAIN;

if (!SHOP_ID || !SHOP_DOMAIN) {
  console.error('ERROR: SHOP_ID and SHOP_DOMAIN must be set in .env');
  process.exit(1);
}

const SHOPIFY_STORE_URL = `https://${SHOP_DOMAIN}.myshopify.com`;

// ─── Demo config ──────────────────────────────────────────────────────────────
const DEMO_MODE = process.env.DEMO_MODE === 'true';
const DEMO_OTP = process.env.DEMO_OTP || '123456';

// ─── Phone → Email lookup ─────────────────────────────────────────────────────
//
// Shopify Customer Account API requires a real email as the `sub` / accountId.
// After verifying the OTP we fetch the customer's email from your backend so
// the OIDC identity token carries the right subject.
//
// Replace the function body with your actual customer-lookup API call.
// It must return a string (email) on success, or null when not found.
//

// async function lookupEmailByPhone(phone) {
//   // ── DEMO shortcut ──────────────────────────────────────────────────────────
//   if (DEMO_MODE) {
//     // In demo mode every phone maps to a predictable email so you can test
//     // without a real customer database.
//     return `${phone}@demo.example.com`;
//   }

//   // ── Real lookup ────────────────────────────────────────────────────────────
//   // Example: call your own API that knows which email belongs to this phone.
//   //
//   // try {
//   //   const resp = await fetch(`https://your-api.example.com/customers/by-phone/${phone}`, {
//   //     headers: { Authorization: `Bearer ${process.env.INTERNAL_API_KEY}` },
//   //   });
//   //   if (!resp.ok) return null;
//   //   const data = await resp.json();
//   //   return data.email ?? null;
//   // } catch (err) {
//   //   console.error('[lookupEmailByPhone] Error:', err.message);
//   //   return null;
//   // }

//   throw new Error(
//     'lookupEmailByPhone: not implemented. ' +
//     'Add your customer lookup logic or set DEMO_MODE=true.',
//   );
// }

async function lookupEmailByPhone(phone) {
  const formattedPhone = `+91${phone}`;
  const response = await fetch(
    `https://${process.env.SHOP_DOMAIN}.myshopify.com/admin/api/2024-01/graphql.json`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': process.env.SHOPIFY_ADMIN_API_TOKEN,
      },
      body: JSON.stringify({
        query: `query getCustomerByPhone($phone: String!) {
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
}
// ─── OIDC Configuration ───────────────────────────────────────────────────────
const oidcConfig = {
  adapter: RedisAdapter,
  issuer: ISSUER,

  scopes: ['openid', 'email', 'offline_access', 'customer-account-api:full'],

  claims: {
    openid: ['sub'],
    email: ['email', 'email_verified'],
  },

  clients: [{
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
  }],

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
    AuthorizationCode: 300,
    AccessToken: 3600,
    IdToken: 3600,
    RefreshToken: 1209600,
    Interaction: 3600,
    Session: 1209600,
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
    short: { sameSite: 'None', secure: true, httpOnly: true, path: '/', overwrite: true, signed: false },
    long: { sameSite: 'None', secure: true, httpOnly: true, path: '/', overwrite: true, signed: false },
  },

  // accountId is always a verified email address (set in interactionFinished)
  findAccount: async (ctx, id) => {
    if (!id || id === 'undefined' || id === 'null') return undefined;

    const email = id; // accountId is always email

    return {
      accountId: id,
      async claims(use, scope) {
        return {
          sub: email,
          email,
          email_verified: true,
          updated_at: Math.floor(Date.now() / 1000),
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
};

const oidc = new Provider(ISSUER, oidcConfig);
oidc.proxy = true;

// ─── Cookie fix middleware ────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('ngrok-skip-browser-warning', 'true');
  const origSetHeader = res.setHeader.bind(res);
  res.setHeader = function (name, value) {
    if (name.toLowerCase() === 'set-cookie') {
      const cookies = Array.isArray(value) ? value : [value];
      const fixed = cookies.map((c) => {
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

// ─── Request logger ───────────────────────────────────────────────────────────
app.use((req, res, next) => {
  console.log(`📨 ${req.method} ${req.path} | query: ${JSON.stringify(req.query)}`);
  next();
});



// ─── Interaction: GET ─────────────────────────────────────────────────────────
//
// Handles both the initial login prompt AND the consent step that oidc-provider
// injects automatically after a successful login.  Mirrors the working pattern
// from the credential-based flow (file 2).
//
app.get('/interaction/:uid', async (req, res, next) => {
  let interactionDetails;
  try {
    interactionDetails = await oidc.interactionDetails(req, res);
  } catch (err) {
    // Session expired or already consumed — send the user home
    console.log('[Interaction GET] Session not found — redirecting to store');
    return res.redirect(SHOPIFY_STORE_URL);
  }

  try {
    const { uid, params, prompt, session: oidcSession } = interactionDetails;

    // ── Auto-grant consent (same pattern as working flow) ──────────────────
    if (prompt.name === 'consent') {
      console.log('[Interaction GET] Auto-granting consent');

      const { Grant } = oidc;
      let grant = oidcSession?.grantId
        ? await Grant.find(oidcSession.grantId)
        : null;

      if (!grant) {
        grant = new Grant({
          accountId: oidcSession?.accountId,
          clientId: params.client_id,
        });
      }

      const scopeToGrant = params.scope
        ? (params.scope.includes("offline_access")
          ? params.scope
          : `${params.scope} offline_access`)
        : "openid email offline_access";
      grant.addOIDCScope(scopeToGrant);

      const grantId = await grant.save();

      return oidc.interactionFinished(
        req, res,
        { consent: { grantId } },
        { mergeWithLastSubmission: false },
      );
    }

    // ── Normal login prompt — show phone/OTP form ──────────────────────────
    console.log('[Interaction GET] Showing login form for uid:', uid);
    res.render('login', { uid, error: null });
  } catch (err) {
    next(err);
  }
});

// ─── Interaction: send OTP ────────────────────────────────────────────────────
app.post('/interaction/:uid/send-otp', express.urlencoded({ extended: false }), async (req, res, next) => {
  try {
    const { phone } = req.body;
    const { uid } = req.params;

    if (!phone || !/^[6-9]\d{9}$/.test(phone)) {
      return res.render('login', {
        uid,
        error: 'Please enter a valid 10-digit Indian mobile number.',
      });
    }

    if (DEMO_MODE) {
      console.log(`[DEMO] Skipping MSG91. OTP for ${phone} is: ${DEMO_OTP}`);
      return res.render('verify', { uid, phone, reqId: null, error: null, demoOtp: DEMO_OTP });
    }

    const mobile = `91${phone}`;
    const result = await sendOTP(mobile);
    if (!result.success) {
      return res.render('login', { uid, error: result.message });
    }

    console.log(`OTP sent to ${mobile}, reqId: ${result.reqId}`);
    res.render('verify', { uid, phone, reqId: result.reqId || null, error: null, demoOtp: null });
  } catch (err) {
    next(err);
  }
});

// ─── Interaction: verify OTP ──────────────────────────────────────────────────
//
// KEY FIX: after OTP verification we look up the customer's email and use THAT
// as the accountId — never the raw phone number.  This ensures findAccount and
// the OIDC claims all carry a real email as `sub`, which Shopify requires.
//
app.post('/interaction/:uid/verify-otp', express.urlencoded({ extended: false }), async (req, res, next) => {
  try {
    const { phone, otp, reqId } = req.body;
    const { uid } = req.params;

    if (!otp || String(otp).length < 4) {
      return res.render('verify', {
        uid, phone, reqId: reqId || null,
        error: 'Please enter the OTP.',
        demoOtp: DEMO_MODE ? DEMO_OTP : null,
      });
    }

    // ── Verify the OTP ─────────────────────────────────────────────────────
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

    // ── OTP verified — resolve the customer's email ────────────────────────
    //
    // This is the critical step your original code was missing.
    // We MUST use email as accountId, not phone, because:
    //   1. findAccount returns claims with sub = accountId
    //   2. Shopify maps sub → customer record by email
    //
    const email = await lookupEmailByPhone(phone);
    if (!email) {
      return res.render('verify', {
        uid, phone, reqId: reqId || null,
        error: 'No account found for this number. Please contact support.',
        demoOtp: DEMO_MODE ? DEMO_OTP : null,
      });
    }

    console.log(`✅ OTP verified. Logging in as: ${email}`);

    // ── Finish the login step ──────────────────────────────────────────────
    //
    // We only finish the LOGIN step here.  The consent step is handled
    // automatically in the GET handler above — same pattern as the working flow.
    //
    await oidc.interactionFinished(
      req, res,
      {
        login: {
          accountId: email,
          remember: true,
        },
      },
      { mergeWithLastSubmission: false },
    );
  } catch (err) {
    console.error('❌ verify-otp ERROR:', err.message, err.stack);
    next(err);
  }
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Keep-alive ping every 4 minutes
setInterval(async () => {
  try {
    await fetch(`https://${process.env.NGROK_HOST}/health`);
    console.log('🏓 Keep-alive ping sent');
  } catch (err) {
    console.error('Keep-alive failed:', err.message);
  }
}, 4 * 60 * 1000);

// ─── OIDC Events ──────────────────────────────────────────────────────────────
oidc.on('authorization.success', (ctx) => {
  console.log('✅ authorization.success → redirecting to:', ctx.oidc?.redirectUri);
});

oidc.on('authorization.error', (ctx, err) => {
  console.error('❌ authorization.error:', err.message, JSON.stringify(ctx.oidc?.params));
});

oidc.on('grant.success', (ctx) => {
  console.log('✅ grant.success — token issued to:', ctx.oidc?.client?.clientId);
  console.log('   grant_type:', ctx.oidc?.params?.grant_type);
});

oidc.on('grant.error', (ctx, err) => {
  console.error('❌ grant.error:', err.message);
  console.error('   body:', ctx.request?.body);
});

oidc.on('server_error', (ctx, err) => {
  console.error('❌ server_error:', err.message, err.stack);
});

// ─── Mount OIDC ───────────────────────────────────────────────────────────────
app.use(oidc.callback());

// ─── Global error handler ─────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[Server Error]', err);
  res.status(err.status || 500).json({
    error: err.error || 'server_error',
    error_description: err.error_description || err.message,
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────
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
    console.log('[DEMO NUMBER] Bypassing MSG91');
    return { success: true, reqId: 'demo' };
  }
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
  if (mobile === '919193521876') {
    console.log('[DEMO NUMBER] Verifying demo OTP:', otp);
    return { success: otp === '123456' };
  }
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
