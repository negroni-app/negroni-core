import { generateEcdhKeyPair, mul, generateAesKey } from './crypto';

describe('crypto', () => {
  describe('generateEcdhKeyPair', () => {
    it('should return ECDH key pair', () => {
      const pair = generateEcdhKeyPair();
      expect(pair).toBeDefined();
    });
  });
  describe('mul', () => {
    it('should give Alice and Bob the same X value', () => {
      const Alice = generateEcdhKeyPair();
      const Bob = generateEcdhKeyPair();
      const Ab = mul(Alice.getPublic(), Bob.getPrivate())
        .getX()
        .toString('hex');
      const aB = mul(Bob.getPublic(), Alice.getPrivate())
        .getX()
        .toString('hex');
      expect(Ab).toBe(aB);
    });
    it('should give Alice, Bob & Carol the same X value', () => {
      const Alice = generateEcdhKeyPair();
      const Bob = generateEcdhKeyPair();
      const Carol = generateEcdhKeyPair();
      const Ab = mul(Alice.getPublic(), Bob.getPrivate());
      const Bc = mul(Bob.getPublic(), Carol.getPrivate());
      const Ca = mul(Carol.getPublic(), Alice.getPrivate());
      const Abc = mul(Ab, Carol.getPrivate()).getX().toString();
      const aBc = mul(Bc, Alice.getPrivate()).getX().toString();
      const abC = mul(Ca, Bob.getPrivate()).getX().toString();
      expect(Abc).toBe(aBc);
      expect(Abc).toBe(abC);
    });
    it('should give Alice, Bob & Carol the same X value with given G', () => {
      const g = generateEcdhKeyPair().getPublic();
      const Alice = generateEcdhKeyPair().getPrivate();
      const Bob = generateEcdhKeyPair().getPrivate();
      const Carol = generateEcdhKeyPair().getPrivate();
      const gA = mul(g, Alice);
      const gB = mul(g, Bob);
      const gC = mul(g, Carol);
      const gAB = mul(gA, Bob);
      const gBC = mul(gB, Carol);
      const gCA = mul(gC, Alice);
      const carolResult = mul(gAB, Carol).getX().toString();
      const aliceResult = mul(gBC, Alice).getX().toString();
      const bobResult = mul(gCA, Bob).getX().toString();
      expect(aliceResult).toBe(bobResult);
      expect(aliceResult).toBe(carolResult);
    });
  });
  describe('generateAesKey', () => {
    it('should create Alice AES key with EC base point', async () => {
      const Alice = generateEcdhKeyPair();
      const Bob = generateEcdhKeyPair();
      const sharedSecret = mul(Bob.getPublic(), Alice.getPrivate());
      const key = await generateAesKey(sharedSecret);
      expect(key).toBeDefined();
    });
    it('should enable Bob to decrypt ciphertext from Alice', async () => {
      const plainText = `this is my secret text!`;
      const enc = new TextEncoder();
      const encodedText = enc.encode(plainText);
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const Alice = generateEcdhKeyPair();
      const Bob = generateEcdhKeyPair();
      const aliceSecret = mul(Bob.getPublic(), Alice.getPrivate());
      const bobSecret = mul(Alice.getPublic(), Bob.getPrivate());
      const aliceKey = await generateAesKey(aliceSecret);
      const bobKey = await generateAesKey(bobSecret);
      const cipherText = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        aliceKey,
        encodedText,
      );
      const decryptedText = await window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv,
        },
        bobKey,
        cipherText,
      );
      const dec = new TextDecoder();
      const decodedText = dec.decode(decryptedText);
      expect(plainText).toBe(decodedText);
    });
  });
});
