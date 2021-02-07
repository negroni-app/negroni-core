import BN from 'bn.js';
import { curve, ec as EC } from 'elliptic';

const ec = new EC('curve25519');

export function generateEcdhKeyPair(): EC.KeyPair {
  return ec.genKeyPair();
}

export function mul(key: curve.base.BasePoint, priv: BN): curve.base.BasePoint {
  return key.mul(priv);
}

export function generateAesKey(key: curve.base.BasePoint): Promise<CryptoKey> {
  return window.crypto.subtle.importKey(
    'jwk',
    {
      key_ops: ['encrypt', 'decrypt'],
      ext: false,
      kty: 'oct',
      k: key.getX().toBuffer().toString('base64'),
      alg: 'A256GCM',
    },
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}
