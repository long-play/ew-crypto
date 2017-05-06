class Crypto {
  constructor() {
  }

  generateKeys(length = 256) {
    this.length = length;
    this.iv = Crypto._arrayBufferToBase64(Crypto._crypto().getRandomValues(new Uint8Array(16)));
    const promise = Crypto._subtle().generateKey({
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

    const promise = Crypto._subtle().exportKey('jwk', this.cryptoKey).then( (keydata) => {
      this.key = Crypto._arrayBufferToBase64(keydata);
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
    const keydata = Crypto._base64ToArrayBuffer(this.key);
    const promise = Crypto._importKey(keydata, ['encrypt', 'decrypt']).then( (pk) => {
      this.cryptoKey = pk;
      return Promise.resolve(this);
    });
    return promise;
  }

  encrypt(textData) {
    const promise = Crypto._subtle().encrypt({
        name: 'AES-CBC',
        iv: Crypto._base64ToArrayBuffer(this.iv)
      },
      this.cryptoKey,
      Crypto._stringToArrayBuffer(textData)
    ).then( (encryptedBuffer) => {
      return Promise.resolve(Crypto._arrayBufferToBase64(encryptedBuffer));
    });
    return promise;
  }

  decrypt(encryptedTextData) {
    const promise = Crypto._subtle().decrypt({
        name: 'AES-CBC',
        iv: Crypto._base64ToArrayBuffer(this.iv)
      },
      this.cryptoKey,
      Crypto._base64ToArrayBuffer(encryptedTextData)
    ).then( (decryptedBuffer) => {
      return Promise.resolve(Crypto._arrayBufferToString(decryptedBuffer));
    });
    return promise;
  }

  // private methods
  static _crypto() {
    return window.crypto;
  }

  static _subtle() {
    return window.crypto.webkitSubtle;
  }

  static _importKey(keydata, purposes) {
    if (!keydata) return Promise.resolve(null);

    const promise = Crypto._subtle().importKey(
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

