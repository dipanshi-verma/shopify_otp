const { generateKeyPairSync, createPrivateKey } = require('crypto');
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

// Save PEM files
fs.writeFileSync(path.join(keysDir, 'private.pem'), privateKey);
fs.writeFileSync(path.join(keysDir, 'public.pem'), publicKey);

// Build proper JWKS with all private key components for oidc-provider signing
const privateKeyObj = createPrivateKey(privateKey);
const privateJwk = privateKeyObj.export({ format: 'jwk' });

const fullJwks = {
  keys: [{ ...privateJwk, use: 'sig', alg: 'RS256', kid: 'key-1' }],
};

fs.writeFileSync(path.join(keysDir, 'jwks.json'), JSON.stringify(fullJwks, null, 2));

console.log('✅ Keys generated successfully in .keys/');
console.log('   - private.pem');
console.log('   - public.pem');
console.log('   - jwks.json');

// Verify the keys are correct
const loaded = JSON.parse(fs.readFileSync(path.join(keysDir, 'jwks.json'), 'utf8'));
const keyFields = Object.keys(loaded.keys[0]);
console.log('\n🔍 Key fields present:', keyFields.join(', '));

const required = ['kty', 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'];
const missing = required.filter(f => !keyFields.includes(f));
if (missing.length > 0) {
  console.error('❌ Missing required key fields:', missing.join(', '));
  process.exit(1);
} else {
  console.log('✅ All required RSA key components present!');
}
