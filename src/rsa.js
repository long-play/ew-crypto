class CryptoRSA {
  constructor() {
  }

  generateKeys(modulusLength = 2048) {
    this.modulusLength = modulusLength;
    const promise = CryptoUtil.crypto().generateKey({
        name: 'RSA-OAEP',
        modulusLength: this.modulusLength,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: 'SHA-1' },
      },
      true,
      ['encrypt', 'decrypt']
    ).then( (key) => {
      this.cryptoPublicKey = key.publicKey;
      this.cryptoPrivateKey = key.privateKey;
      return Promise.resolve(this);
    });
    return promise;
  }

  exportKeys() {
    if (!this.cryptoPrivateKey ||
        this.cryptoPrivateKey.extractable !== true ||
        !this.cryptoPublicKey ||
        this.cryptoPublicKey.extractable !== true) {
        // there is no one of the keys of one of them is not extractable
        return Promise.reject(new Error('there is no one of the keys of one of them is not extractable'));
    }

    const promise = CryptoUtil.crypto().exportKey('jwk', this.cryptoPrivateKey).then( (keydata) => {
      this.privateKey = CryptoUtil.arrayBufferToBase64(keydata);
      return CryptoUtil.crypto().exportKey('jwk', this.cryptoPublicKey);
    }).then( (keydata) => {
      this.publicKey = CryptoUtil.arrayBufferToBase64(keydata);
      return Promise.resolve(this);
    });
    return promise;
  }

  importKeys(privateKey, publicKey) {
    if (!privateKey && !publicKey) {
        return Promise.reject('both empty keys are not allowed');
    }

    this.privateKey = privateKey;
    this.publicKey = publicKey;
    const privateKeydata = CryptoUtil.base64ToArrayBuffer(this.privateKey);
    const publicKeydata = CryptoUtil.base64ToArrayBuffer(this.publicKey);
    const promise = CryptoUtil.importKey(privateKeydata, 'decrypt').then( (pk) => {
      this.cryptoPrivateKey = pk;
      return CryptoUtil.importKey(publicKeydata, 'encrypt');
    }).then( (pk) => {
      this.cryptoPublicKey = pk;
      return Promise.resolve(this);
    });
    return promise;
  }

  encrypt(textData) {
    const promise = CryptoUtil.crypto().encrypt({
        name: 'RSA-OAEP',
        hash: { name: 'SHA-1' },
      },
      this.cryptoPublicKey,
      CryptoUtil.stringToArrayBuffer(textData)
    ).then( (encryptedBuffer) => {
      return Promise.resolve(CryptoUtil.arrayBufferToBase64(encryptedBuffer));
    });
    return promise;
  }

  decrypt(encryptedTextData) {
    const promise = CryptoUtil.crypto().decrypt({
        name: 'RSA-OAEP',
        hash: { name: 'SHA-1' },
      },
      this.cryptoPrivateKey,
      CryptoUtil.base64ToArrayBuffer(encryptedTextData)
    ).then( (decryptedBuffer) => {
      return Promise.resolve(CryptoUtil.arrayBufferToString(decryptedBuffer));
    });
    return promise;
  }

  // private methods
  static _importKey(keydata, purpose) {
    if (!keydata) return Promise.resolve(null);

    const promise = CryptoUtil.crypto().importKey(
      'jwk',
      keydata,
      {
        name: 'RSA-OAEP',
        hash: { name: 'SHA-1' },
      },
      false,
      [purpose]
    );
    return promise;
  }
}

