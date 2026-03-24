const { generateKeyPairSync } = require('crypto');
const fs = require('fs');
const path = require('path');

const keysDir = path.join(__dirname, '.keys');
if (!fs.existsSync(keysDir)) fs.mkdirSync(keysDir);

console.log('Generating RSA key pair...');

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Build a minimal JWK set for oidc-provider
const { createPublicKey } = require('crypto');
const pubKeyObj = createPublicKey(publicKey);
const jwk = pubKeyObj.export({ format: 'jwk' });

const jwks = {
  keys: [
    {
      ...jwk,
      kty: 'RSA',
      use: 'sig',
      alg: 'RS256',
      kid: 'shopify-otp-idp-key-1',
      // Include private key components for signing
      d: Buffer.from(privateKey).toString('base64'),
    },
  ],
};

// Better: use jose library approach — store PEM files and let oidc-provider load them
fs.writeFileSync(path.join(keysDir, 'private.pem'), privateKey);
fs.writeFileSync(path.join(keysDir, 'public.pem'), publicKey);

// Build proper JWKS using the full key
const privateKeyObj = require('crypto').createPrivateKey(privateKey);
const privateJwk = privateKeyObj.export({ format: 'jwk' });
const fullJwks = {
  keys: [{ ...privateJwk, use: 'sig', alg: 'RS256', kid: 'key-1' }],
};

fs.writeFileSync(path.join(keysDir, 'jwks.json'), JSON.stringify(fullJwks, null, 2));

console.log('✅ Keys generated successfully in .keys/');
console.log('   - private.pem');
console.log('   - public.pem');
console.log('   - jwks.json');
