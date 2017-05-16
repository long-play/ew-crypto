class Crypto {
  constructor(rsaLength = 2048, aesLength = 256) {
    this.rsa = new CryptoRSA();
    this.aes = new CryptoAES();
    this.rsaLength = rsaLength;
    this.aesLength = aesLength;
  }

  generateKeys() {
    return this.rsa.generateKeys(this.rsaLength);
  }

  importKeys(privateKey, publicKey) {
    return this.rsa.importKeys(privateKey, publicKey);
  }

  exportKeys() {
    return this.rsa.exportKeys();
  }

  encrypt(textData) {
    let encryptedData = null;
    let encryptedKey = null;
    const textData64 = this._encode64(textData);

    const promise = this.aes.generateKeys(this.aesLength).then( (aes) => {
      return this.aes.exportKeys();
    }).then( (aes) => {
      return this.aes.encrypt(textData64);
    }).then( (encrypted) => {
      const key = this._composeKeyIV(this.aes.key, this.aes.iv);
      encryptedData = encrypted;
      return this.rsa.encrypt(key);
    }).then( (encrypted) => {
      encryptedKey = encrypted;
      return Promise.resolve(this._composeEncryptedKeyData(encryptedKey, encryptedData));
    });
    return promise;
  }

  decrypt(encryptedTextData) {
    const encryptedKey = this._extractEncryptedKey(encryptedTextData);
    const encryptedData = this._extractEncryptedData(encryptedTextData);

    const promise = this.rsa.decrypt(encryptedKey).then( (decryptedKey) => {
      const aesIV = this._extractAESIV(decryptedKey);
      const aesKey = this._extractAESKey(decryptedKey);
      return this.aes.importKeys(aesKey, aesIV);
    }).then( (aes) => {
      return this.aes.decrypt(encryptedData);
    }).then( (decrypted64) => {
      const decrypted = this._decode64(decrypted64);
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
    const idx = keyData.indexOf(' ');
    return keyData.substring(0, idx);
  }

  _extractEncryptedData(keyData) {
    const idx = keyData.indexOf(' ');
    return keyData.substring(idx + 1);
  }

  _composeEncryptedKeyData(key, data) {
    return `${key} ${data}`;
  }

  _extractAESIV(key) {
    const idx = keyData.indexOf(' ');
    return keyData.substring(0, idx);
  }

  _extractAESKey(key) {
    const idx = keyData.indexOf(' ');
    return keyData.substring(idx + 1);
  }

  _composeKeyIV(key, iv) {
    return `${iv} ${key}`;
  }
}
