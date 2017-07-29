class CryptoAESCBC {
  constructor() {
  }

  generateKeys(length = 256) {
    this.length = length;
    this.iv = CryptoUtil.arrayBufferToBase64(CryptoUtil.crypto().getRandomValues(new Uint8Array(16)));
    const promise = CryptoUtil.subtle().generateKey({
        name: 'AES-CBC',
        length: this.length
      },
      true,
      ['encrypt', 'decrypt']
    ).then( (key) => {
      this.cryptoKey = key;
      return Promise.resolve(this);
    });
    return promise;
  }

  createKeyFromHex(hexKey, iv) {
    const key = CryptoAESCBC._createKeyFromHex(hexKey);
    this.key = CryptoUtil.jsonToBase64(key);
    this.length = (hexKey.length / 2) * 8;
    if (iv) {
      this.iv = CryptoUtil.hexToBase64(iv);
    } else {
      this.iv = CryptoUtil.arrayBufferToBase64(CryptoUtil.crypto().getRandomValues(new Uint8Array(16)));
    }

    const keydata = CryptoUtil.base64ToJwk(this.key);
    const promise = CryptoAESCBC._importKey(keydata, ['encrypt', 'decrypt']).then( (pk) => {
      this.cryptoKey = pk;
      return Promise.resolve(this);
    });
    return promise;
  }

  exportKeys() {
    if (!this.cryptoKey ||
        this.cryptoKey.extractable !== true ||
        !this.iv) {
        // there is no one of the keys extractable
        return Promise.reject(new Error('there is no extractable key or IV'));
    }

    const promise = CryptoUtil.subtle().exportKey('jwk', this.cryptoKey).then( (keydata) => {
      this.key = CryptoUtil.jwkToBase64(keydata);
      return Promise.resolve(this);
    });
    return promise;
  }

  importKeys(key, iv) {
    if (!key || !iv) {
        return Promise.reject('empty key or initial vector are not allowed');
    }

    this.key = key;
    this.iv = iv;
    const keydata = CryptoUtil.base64ToJwk(this.key);
    const promise = CryptoAESCBC._importKey(keydata, ['encrypt', 'decrypt']).then( (pk) => {
      this.cryptoKey = pk;
      return Promise.resolve(this);
    });
    return promise;
  }

  encrypt(textData) {
    const promise = CryptoUtil.subtle().encrypt({
        name: 'AES-CBC',
        iv: CryptoUtil.base64ToArrayBuffer(this.iv)
      },
      this.cryptoKey,
      CryptoUtil.stringToArrayBuffer(textData)
    ).then( (encryptedBuffer) => {
      return Promise.resolve(CryptoUtil.arrayBufferToBase64(encryptedBuffer));
    });
    return promise;
  }

  decrypt(encryptedTextData) {
    const promise = CryptoUtil.subtle().decrypt({
        name: 'AES-CBC',
        iv: CryptoUtil.base64ToArrayBuffer(this.iv)
      },
      this.cryptoKey,
      CryptoUtil.base64ToArrayBuffer(encryptedTextData)
    ).then( (decryptedBuffer) => {
      return Promise.resolve(CryptoUtil.arrayBufferToString(decryptedBuffer));
    });
    return promise;
  }

  // private methods
  static _createKeyFromHex(hexKey) {
    const key = {
      kty: 'oct',
      k: CryptoUtil.hexToBase64u(hexKey),
      alg: 'A256CBC',
      ext: true
    };
    return key;
  }

  static _importKey(keydata, purposes) {
    if (!keydata) return Promise.resolve(null);

    const promise = CryptoUtil.subtle().importKey(
      'jwk',
      keydata,
      {
        name: 'AES-CBC'
      },
      false,
      purposes
    );
    return promise;
  }

}

