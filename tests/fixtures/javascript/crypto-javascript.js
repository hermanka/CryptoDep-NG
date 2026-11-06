const crypto = require('node:crypto');
const legacy = require('crypto');
import * as esm from 'node:crypto';
import { createHash as hash } from 'crypto';
import { generateKeyPairSync } from 'node:crypto';
import defaultCrypto from 'crypto';
const { createHash: aliasedHash } = require('node:crypto');
const { createHmac } = require('crypto');

// ruleid: crypto-javascript-node-api
crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
// ruleid: crypto-javascript-node-api
legacy.createHash('sha256').update('message').digest('hex');
// ruleid: crypto-javascript-node-api
esm.createCipheriv('aes-128-gcm', key, iv);
// ruleid: crypto-javascript-node-api
hash('md5');
// ruleid: crypto-javascript-node-api
generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
// ruleid: crypto-javascript-node-api
crypto.createHmac('sha256', key);
// ruleid: crypto-javascript-node-default-api
defaultCrypto.createHash('sha512');
// ruleid: crypto-javascript-node-api
aliasedHash('sha1');
// ruleid: crypto-javascript-node-api
createHmac('sha256', key);
// ruleid: crypto-javascript-node-api
require('crypto').createHash('sha384');

// ok: crypto-javascript-node-api
unrelated.createHash('sha256');
// ok: crypto-javascript-node-api
console.log('RSA AES SHA-256');

// ruleid: crypto-javascript-webcrypto-string
crypto.subtle.digest('SHA-256', data);
// ruleid: crypto-javascript-webcrypto-object
window.crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
// ruleid: crypto-javascript-webcrypto-object
globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
// ruleid: crypto-javascript-webcrypto-object
crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, data);

// ok: crypto-javascript-webcrypto-object, crypto-javascript-webcrypto-string
unrelated.subtle.digest('SHA-256', data);
