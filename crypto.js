class Crypto {
  constructor(rsaLength = 2048, aesLength = 256) {
    this.rsa = CryptoRSA();
    this.aes = CryptoAES();
    this.rsaLength = rsaLength;
    this.aesLength = aesLength;
  }

  generateKeys() {
    return this.rsa.generateKeys(this.rsaLength);
  }

  importKeys(privateKey, publicKey) {
    return this.rsa.importKeys(privateKey, publicKey);
  }

  encrypt(textData) {
    let encryptedData = null;
    let encryptedKey = null;
    const textData64 = _encode64(textData);

    const promise = this.aes.generateKeys(this.aesLength).then( (aes) => {
      return this.aes.exportKeys();
    }).then( (aes) => {
      return this.aes.encrypt(textData64);
    }).then( (encrypted) => {
      const key = _composeKeyIV(this.aes.key, this.aes.iv);
      encryptedData = encrypted;
      return this.rsa.encrypt(key);
    }).then( (encrypted) => {
      encryptedKey = encrypted;
      return Promise.resolve(_composeEncryptedKeyData(encryptedKey, encryptedData));
    });
    return promise;
  }

  decrypt(encryptedTextData) {
    const encryptedKey = _extractEncryptedKey(encryptedTextData);
    const encryptedData = _extractEncryptedData(encryptedTextData);

    const promise = this.rsa.decrypt(encryptedKey).then( (decryptedKey) => {
      const aesIV = _extractAESIV(decryptedKey);
      const aesKey = _extractAESKey(decryptedKey);
      return this.aes.importKeys(aesKey, aesIV);
    }).then( (aes) => {
      return this.aes.decrypt(encryptedData);
    }).then( (decrypted64) => {
      const decrypted = _decode64(decrypted64);
      return Promise.resolve(decrypted);
    });
    return promise;
  }

  // private methods
  _encode64(text) {
    return text;
  }

  _decode64(text64) {
    return text64;
  }

  _extractEncryptedKey(keyData) {
    return keyData.substring(0, 32);
  }

  _extractEncryptedData(keyData) {
    return keyData.substring(32);
  }

  _composeEncryptedKeyData(key, data) {
    return key + data;
  }

  _extractAESIV(key) {
    return keyData.substring(0, 32);
  }

  _extractAESKey(key) {
    return keyData.substring(32);
  }

  _composeKeyIV(key, iv) {
    return iv + key;
  }
}
