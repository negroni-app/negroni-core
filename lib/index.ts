import BN from 'bn.js';
import { curve, ec as EC } from 'elliptic';

const ec = new EC('curve25519');

const AESGCM = 'AES-GCM'

// Type aliasing for readability
type BasePoint = curve.base.BasePoint

/**
 * Create key pair on elliptic curve diffie-hellman. Generated key pair is from elliptic.
 */
function generateEcdhKeyPair(): EC.KeyPair {
  return ec.genKeyPair();
}

/**
 * Execute multiplication on base (EC point) and private key. Use this when you need to generate shared secret.
 * 
 * @param key 
 * @param priv 
 */
function mul(key: BasePoint, priv: BN): BasePoint {
  return key.mul(priv);
}

/**
 * Generate symmetric key from secret. Result promise can be used in decryption or encrytion.
 * 
 * @param key 
 */
async function generateAESKey(key: BasePoint): Promise<CryptoKey> {
  const result = await window.crypto.subtle.importKey(
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
  
  return result
}

async function decryption(target: ArrayBuffer, key: CryptoKey, iv: Uint8Array): Promise<string> {
  const ivObject = { name: AESGCM, iv }
  
  const result = await window.crypto.subtle.decrypt(
    ivObject,
    key,
    target,
  )
  const decodedResult = new TextDecoder().decode(result)
  
  return decodedResult
}

async function encryption(target: string, key: CryptoKey, iv: Uint8Array): Promise<ArrayBuffer> {
  const ivObject = { name: AESGCM, iv }
  
  const encodedTarget = new TextEncoder().encode(target)
  
  const result = await window.crypto.subtle.encrypt(
    ivObject,
    key,
    encodedTarget,
  )
  
  return result
}

export default {
  generateEcdhKeyPair,
  mul,
  generateAESKey,
  decryption,
  encryption,
}
