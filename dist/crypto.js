class CryptoUtil {
  constructor() {
  }

  static crypto() {
    return window.crypto;
  }

  static subtle() {
    return window.crypto.webkitSubtle;
  }

  static arrayBufferToString(buffer) {
    if (!buffer) return null;

    let string = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
      string += String.fromCharCode(bytes[i]);
    }
    return string;
  }

  static arrayBufferToBase64(buffer) {
    if (!buffer) return null;

    const binary = CryptoUtil.arrayBufferToString(buffer);
    return window.btoa(binary);
  }

  static stringToArrayBuffer(string) {
    if (!string) return null;

    const len = string.length;
    const bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
      bytes[i] = string.charCodeAt(i);
    }
    return bytes.buffer;
  }

  static base64ToArrayBuffer(base64) {
    if (!base64) return null;

    const binaryString = window.atob(base64);
    return CryptoUtil.stringToArrayBuffer(binaryString);
  }
}
class CryptoAES {
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

  exportKeys() {
    if (!this.cryptoKey ||
        this.cryptoKey.extractable !== true ||
        !this.iv) {
        // there is no one of the keys extractable
        return Promise.reject(new Error('there is no extractable key or IV'));
    }

    const promise = CryptoUtil.subtle().exportKey('jwk', this.cryptoKey).then( (keydata) => {
      this.key = CryptoUtil.arrayBufferToBase64(keydata);
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
    const keydata = CryptoUtil.base64ToArrayBuffer(this.key);
    const promise = CryptoAES._importKey(keydata, ['encrypt', 'decrypt']).then( (pk) => {
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

class CryptoRSA {
  constructor() {
  }

  generateKeys(modulusLength = 2048) {
    this.modulusLength = modulusLength;
    const promise = CryptoUtil.subtle().generateKey({
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

    const promise = CryptoUtil.subtle().exportKey('jwk', this.cryptoPrivateKey).then( (keydata) => {
      this.privateKey = CryptoUtil.arrayBufferToBase64(keydata);
      return CryptoUtil.subtle().exportKey('jwk', this.cryptoPublicKey);
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
    const promise = CryptoRSA._importKey(privateKeydata, 'decrypt').then( (pk) => {
      this.cryptoPrivateKey = pk;
      return CryptoRSA._importKey(publicKeydata, 'encrypt');
    }).then( (pk) => {
      this.cryptoPublicKey = pk;
      return Promise.resolve(this);
    });
    return promise;
  }

  encrypt(textData) {
    const promise = CryptoUtil.subtle().encrypt({
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
    const promise = CryptoUtil.subtle().decrypt({
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

    const promise = CryptoUtil.subtle().importKey(
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
