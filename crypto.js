class Crypto {
  constructor() {
  }

  generateKeys(modulusLength = 2048) {
    this.modulusLength = modulusLength;
    const promise = Crypto._crypto().generateKey({
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

    const promise = Crypto._crypto().exportKey('jwk', this.cryptoPrivateKey).then( (keydata) => {
      this.privateKey = Crypto._arrayBufferToBase64(keydata);
      return Crypto._crypto().exportKey('jwk', this.cryptoPublicKey);
    }).then( (keydata) => {
      this.publicKey = Crypto._arrayBufferToBase64(keydata);
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
    const privateKeydata = Crypto._base64ToArrayBuffer(this.privateKey);
    const publicKeydata = Crypto._base64ToArrayBuffer(this.publicKey);
    const promise = Crypto._importKey(privateKeydata, 'decrypt').then( (pk) => {
      this.cryptoPrivateKey = pk;
      return Crypto._importKey(publicKeydata, 'encrypt');
    }).then( (pk) => {
      this.cryptoPublicKey = pk;
      return Promise.resolve(this);
    });
    return promise;
  }

  encrypt(textData) {
    const promise = Crypto._crypto().encrypt({
        name: 'RSA-OAEP',
        hash: { name: 'SHA-1' },
      },
      this.cryptoPublicKey,
      Crypto._stringToArrayBuffer(textData)
    ).then( (encryptedBuffer) => {
      return Promise.resolve(Crypto._arrayBufferToBase64(encryptedBuffer));
    });
    return promise;
  }

  decrypt(encryptedTextData) {
    const promise = Crypto._crypto().decrypt({
        name: 'RSA-OAEP',
        hash: { name: 'SHA-1' },
      },
      this.cryptoPrivateKey,
      Crypto._base64ToArrayBuffer(encryptedTextData)
    ).then( (decryptedBuffer) => {
      return Promise.resolve(Crypto._arrayBufferToString(decryptedBuffer));
    });
    return promise;
  }

  // private methods
  static _crypto() {
    return window.crypto.webkitSubtle;
  }

  static _importKey(keydata, purpose) {
    if (!keydata) return Promise.resolve(null);

    const promise = Crypto._crypto().importKey(
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

  static _arrayBufferToString(buffer) {
    if (!buffer) return null;

    let string = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
      string += String.fromCharCode(bytes[i]);
    }
    return string;
  }

  static _arrayBufferToBase64(buffer) {
    if (!buffer) return null;

    const binary = Crypto._arrayBufferToString(buffer);
    return window.btoa(binary);
  }

  static _stringToArrayBuffer(string) {
    if (!string) return null;

    const len = string.length;
    const bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
      bytes[i] = string.charCodeAt(i);
    }
    return bytes.buffer;
  }

  static _base64ToArrayBuffer(base64) {
    if (!base64) return null;

    const binaryString = window.atob(base64);
    return Crypto._stringToArrayBuffer(binaryString);
  }
}

