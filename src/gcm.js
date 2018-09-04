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
    if (!this._cryptoKey ||
        this._cryptoKey.extractable !== true) {
        // there is no one of the keys extractable
        return Promise.reject(new Error('there is no extractable key or IV'));
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
    //todo: check the key and iv are hex string or ArrayBuffer of appropriate length

    const keydata = key; // or convert if hex string
    const promise = this._util.subtle.importKey(
        'raw',
        keydata,
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
    //todo; check if cryptoKey exist
    //todo: check if plaintext is ArrayBuffer or convert it if hex string
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
      const encrypted = {
        ciphertext,
        iv: iv
      };
      //todo: debug
      console.log(this._util.bufferToHex(ciphertext));
      return Promise.resolve(encrypted);
    });
    return promise;
  }

  decrypt(ciphertext, iv, note) {
    //todo; check if cryptoKey exist
    //todo: check if ciphertext and note are ArrayBuffer or convert it if hex string
    const promise = this._util.subtle.decrypt({
        name: 'AES-GCM',
        iv: iv,
        additionalData: note,
        tagLength: 128
      },
      this._cryptoKey,
      ciphertext
    ).then( (plaintext) => {
      return Promise.resolve(plaintext);
    });
    return promise;
  }
}

