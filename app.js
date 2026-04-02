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
// FORCE HTTPS (NGROK FIX)
// ==============================
app.use((req, res, next) => {
  req.headers['x-forwarded-proto'] = 'https';
  next();
});

// ==============================
// 🔥 RETURN URL STORE (MAIN FIX)
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
  console.log(`[return_to] consumed for ${uid}`);
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
    await redis.set(this.key(id), JSON.stringify(payload), 'EX', expiresIn || 3600);
  }

  async find(id) {
    const data = await redis.get(this.key(id));
    return data ? JSON.parse(data) : undefined;
  }

  async destroy(id) {
    await redis.del(this.key(id));
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
  const formattedPhone = `+91${phone}`;

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
}

// ==============================
// OIDC CONFIG
// ==============================
const oidc = new Provider(ISSUER, {
  adapter: RedisAdapter,

  extraParams: ['return_to'], // 🔥 CRITICAL

  clients: [{
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: [
      `https://shopify.com/authentication/${SHOP_ID}/login/external/callback`,
      `https://${SHOP_DOMAIN}.account.myshopify.com/authentication/login/external/callback`,
    ],
  }],

  jwks: loadJWKS(),

  findAccount: async (ctx, id) => ({
    accountId: id,
    async claims() {
      return {
        sub: id,
        email: id,
        email_verified: true,
      };
    },
  }),

  interactions: {
    url: async (ctx, interaction) => `/interaction/${interaction.uid}`,
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
app.get('/interaction/:uid', async (req, res) => {
  let details;

  try {
    details = await oidc.interactionDetails(req, res);
  } catch {
    return res.redirect(SHOPIFY_STORE_URL);
  }

  const { uid, params, prompt, session } = details;

  console.log(`[OIDC] prompt=${prompt.name} uid=${uid}`);

  // 🔥 SAVE return_to
  if (params.return_to) {
    saveReturnUrl(uid, params.return_to);
  }

  // ==========================
  // CONSENT
  // ==========================
  if (prompt.name === 'consent') {
    const { Grant } = oidc;

    let grant = session?.grantId
      ? await Grant.find(session.grantId)
      : new Grant({
          accountId: session?.accountId,
          clientId: params.client_id,
        });

    const scope = params.scope || 'openid email offline_access';
    grant.addOIDCScope(scope);

    const grantId = await grant.save();

    consumeReturnUrl(uid);

    return oidc.interactionFinished(
      req,
      res,
      { consent: { grantId } },
      { mergeWithLastSubmission: true }
    );
  }

  // ==========================
  // LOGIN
  // ==========================
  res.render('login', { uid, error: null });
});

// ==============================
// SEND OTP
// ==============================
app.post('/interaction/:uid/send-otp', express.urlencoded({ extended: false }), async (req, res) => {
  const { phone } = req.body;
  const { uid } = req.params;

  if (!phone || !/^[6-9]\d{9}$/.test(phone)) {
    return res.render('login', { uid, error: 'Invalid phone number' });
  }

  if (DEMO_MODE) {
    console.log(`[DEMO OTP]: ${DEMO_OTP}`);
    return res.render('verify', { uid, phone, demoOtp: DEMO_OTP });
  }

  await sendOTP(`91${phone}`);

  res.render('verify', { uid, phone });
});

// ==============================
// VERIFY OTP
// ==============================
app.post('/interaction/:uid/verify-otp', express.urlencoded({ extended: false }), async (req, res) => {
  const { phone, otp } = req.body;

  let verified = DEMO_MODE ? otp === DEMO_OTP : true;

  if (!verified) {
    return res.render('verify', { error: 'Invalid OTP' });
  }

  const email = await lookupEmailByPhone(phone);

  if (!email) {
    return res.render('verify', { error: 'No account found' });
  }

  console.log(`✅ LOGIN SUCCESS: ${email}`);

  await oidc.interactionFinished(
    req,
    res,
    {
      login: {
        accountId: email,
        remember: true,
      },
    },
    { mergeWithLastSubmission: false }
  );
});

// ==============================
// HEALTH
// ==============================
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// ==============================
// START
// ==============================
app.use(oidc.callback());

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Running on ${PORT}`);
});

// ==============================
// MSG91 (UNCHANGED)
// ==============================
async function sendOTP(mobile) {
  console.log("Sending OTP to", mobile);
  return { success: true };
}