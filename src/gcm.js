class CryptoAESGCM {
  constructor() {
    this._util = new CryptoUtil();
  }

  generateKey(length = 256) {
    this._length = length;
    const promise = this._util.subtle.generateKey({
        name: 'AES-GCM',
        length: this._length
      },
      true,
      ['encrypt', 'decrypt']
    ).then( (key) => {
      this._cryptoKey = key;
      return Promise.resolve(this);
    });
    return promise;
  }

  exportKey() {
    if (!this._cryptoKey || this._cryptoKey.extractable !== true) {
        return Promise.reject(new Error('there is no extractable key'));
    }

    const promise = this._util.subtle.exportKey('raw', this._cryptoKey).then( (keydata) => {
      return Promise.resolve(keydata);
    });
    return promise;
  }

  importKey(key) {
    if (!key) {
      return Promise.reject('empty key or initial vector are not allowed');
    }

    if (typeof key === 'string') {
      key = CryptoUtil.hexToBuffer(key);
    }

    if (key.length !== 32) {
      return Promise.reject('key has the wrong length');
    }

    const promise = this._util.subtle.importKey(
        'raw',
        key,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
      )
    .then( (cryptoKey) => {
      this._cryptoKey = cryptoKey;
      return Promise.resolve(this);
    });
    return promise;
  }

  encrypt(plaintext, note) {
    if (!this._cryptoKey) {
      return Promise.reject('Crypto key is not initialized');
    }

    if (typeof plaintext === 'string') {
      plaintext = CryptoUtil.hexToBuffer(plaintext);
    }

    if (typeof note === 'string') {
      note = CryptoUtil.hexToBuffer(note);
    }

    const iv = this._util.crypto.getRandomValues(new Uint8Array(12));
    const promise = this._util.subtle.encrypt({
        name: 'AES-GCM',
        iv: iv,
        additionalData: note,
        tagLength: 128
      },
      this._cryptoKey,
      plaintext
    ).then( (ciphertext) => {
      ciphertext = new Uint8Array(ciphertext);
      const encrypted = {
        ciphertext,
        iv: iv
      };
      return Promise.resolve(encrypted);
    });
    return promise;
  }

  decrypt(ciphertext, iv, note) {
    if (!this._cryptoKey) {
      return Promise.reject('Crypto key is not initialized');
    }

    if (typeof ciphertext === 'string') {
      ciphertext = CryptoUtil.hexToBuffer(ciphertext);
    }

    if (typeof iv === 'string') {
      iv = CryptoUtil.hexToBuffer(iv);
    }

    if (iv.length !== 12) {
      return Promise.reject('IV has the wrong length');
    }

    if (typeof note === 'string') {
      note = CryptoUtil.hexToBuffer(note);
    }

    const promise = this._util.subtle.decrypt({
        name: 'AES-GCM',
        iv: iv,
        additionalData: note,
        tagLength: 128
      },
      this._cryptoKey,
      ciphertext
    ).then( (plaintext) => {
      plaintext = new Uint8Array(plaintext);
      return Promise.resolve(plaintext);
    });
    return promise;
  }
}

