import Crypto from '../lib';

describe('Crypto', () => {
  describe('Crypto.generateEcdhKeyPair', () => {
    it('should return ECDH key pair', () => {
      const pair = Crypto.generateEcdhKeyPair();
      expect(pair).toBeDefined();
    });
  });
  describe('Crypto.mul', () => {
    it('should give Alice and Bob the same X value', () => {
      const Alice = Crypto.generateEcdhKeyPair();
      const Bob = Crypto.generateEcdhKeyPair();
      const Ab = Crypto.mul(Alice.getPublic(), Bob.getPrivate())
        .getX()
        .toString('hex');
      const aB = Crypto.mul(Bob.getPublic(), Alice.getPrivate())
        .getX()
        .toString('hex');
      expect(Ab).toBe(aB);
    });
    it('should give Alice, Bob & Carol the same X value', () => {
      const Alice = Crypto.generateEcdhKeyPair();
      const Bob = Crypto.generateEcdhKeyPair();
      const Carol = Crypto.generateEcdhKeyPair();
      const Ab = Crypto.mul(Alice.getPublic(), Bob.getPrivate());
      const Bc = Crypto.mul(Bob.getPublic(), Carol.getPrivate());
      const Ca = Crypto.mul(Carol.getPublic(), Alice.getPrivate());
      const Abc = Crypto.mul(Ab, Carol.getPrivate()).getX().toString();
      const aBc = Crypto.mul(Bc, Alice.getPrivate()).getX().toString();
      const abC = Crypto.mul(Ca, Bob.getPrivate()).getX().toString();
      expect(Abc).toBe(aBc);
      expect(Abc).toBe(abC);
    });
    it('should give Alice, Bob & Carol the same X value with given G', () => {
      const g = Crypto.generateEcdhKeyPair().getPublic();
      const Alice = Crypto.generateEcdhKeyPair().getPrivate();
      const Bob = Crypto.generateEcdhKeyPair().getPrivate();
      const Carol = Crypto.generateEcdhKeyPair().getPrivate();
      const gA = Crypto.mul(g, Alice);
      const gB = Crypto.mul(g, Bob);
      const gC = Crypto.mul(g, Carol);
      const gAB = Crypto.mul(gA, Bob);
      const gBC = Crypto.mul(gB, Carol);
      const gCA = Crypto.mul(gC, Alice);
      const carolResult = Crypto.mul(gAB, Carol).getX().toString();
      const aliceResult = Crypto.mul(gBC, Alice).getX().toString();
      const bobResult = Crypto.mul(gCA, Bob).getX().toString();
      expect(aliceResult).toBe(bobResult);
      expect(aliceResult).toBe(carolResult);
    });
  });
  describe('Crypto.generateAESKey', () => {
    it('should create Alice AES key with EC base point', async () => {
      const Alice = Crypto.generateEcdhKeyPair();
      const Bob = Crypto.generateEcdhKeyPair();
      const sharedSecret = Crypto.mul(Bob.getPublic(), Alice.getPrivate());
      const key = await Crypto.generateAESKey(sharedSecret);
      expect(key).toBeDefined();
    });
    it('should enable Bob to decrypt ciphertext from Alice', async () => {
      const plainText = `this is my secret text!`;
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const Alice = Crypto.generateEcdhKeyPair();
      const Bob = Crypto.generateEcdhKeyPair();
      const aliceSecret = Crypto.mul(Bob.getPublic(), Alice.getPrivate());
      const bobSecret = Crypto.mul(Alice.getPublic(), Bob.getPrivate());
      const aliceKey = await Crypto.generateAESKey(aliceSecret);
      const bobKey = await Crypto.generateAESKey(bobSecret);
      const cipherText = await Crypto.encryption(plainText, aliceKey, iv)
      const decodedText = await Crypto.decryption(cipherText, bobKey, iv)
      expect(plainText).toBe(decodedText);
    });
  });
});
