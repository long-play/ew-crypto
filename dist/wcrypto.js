const createHash = require('create-hash');

class CryptoUtil {
  // Constructor
  constructor() {
    this._crypto = window.crypto;
    this._subtle = this._crypto.subtle;
  }

  // Properties
  get crypto() {
    return this._crypto;
  }

  get subtle() {
    return this._subtle;
  }

  // Public instance functions
  bufferToHex(buffer) {
    return CryptoUtil.bufferToHex(buffer);
  }

  hexToBuffer(hex) {
    return CryptoUtil.hexToBuffer(hex);
  }

  // Public static functions
  static crypto() {
    return window.crypto;
  }

  static subtle() {
    return window.crypto.subtle;
  }

  static bufferToHex(buffer) {
    return '0x' + Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
  }

  static hexToBuffer(hex) {
    return new Uint8Array(CryptoUtil.trimHex(hex).match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  }

  static trimHex(hex) {
    if (hex.slice(0, 2) == '0x') hex = hex.slice(2);
    return hex;
  }

  static sha256(msg) {
    return createHash('sha256').update(msg).digest();
  }
}

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

  encrypt(plaintext, note, iv = null) {
    if (!this._cryptoKey) {
      return Promise.reject('Crypto key is not initialized');
    }

    if (typeof plaintext === 'string') {
      plaintext = CryptoUtil.hexToBuffer(plaintext);
    }

    if (typeof note === 'string') {
      note = CryptoUtil.hexToBuffer(note);
    }

    if (iv === null) {
      iv = this._util.crypto.getRandomValues(new Uint8Array(12));
    }

    if (typeof iv === 'string') {
      iv = CryptoUtil.hexToBuffer(iv);
    }

    if (iv.length !== 12) {
      return Promise.reject('IV has the wrong length');
    }

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


const BN = require('bn.js');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

class WCrypto {
  constructor() {
  }

  encrypt(msg, privKeyFrom, pubKeyTo, note) {
    privKeyFrom = CryptoUtil.trimHex(privKeyFrom);
    pubKeyTo = CryptoUtil.trimHex(pubKeyTo);

    const privateKeyFrom = ec.keyFromPrivate(privKeyFrom, 'hex');
    const publicKeyTo = ec.keyFromPublic(pubKeyTo, 'hex');

    const Px = privateKeyFrom.derive(publicKeyTo.pub).toString('hex');
    const hash = CryptoUtil.sha256(Px);
    const iv = CryptoUtil.sha256(hash).toString('hex').slice(-24);
    return this._aesEncrypt(msg, hash.toString('hex'), iv, note);
  }

  decrypt(msg, privKeyTo, pubKeyFrom, note, iv = null) {
    privKeyTo = CryptoUtil.trimHex(privKeyTo);
    pubKeyFrom = CryptoUtil.trimHex(pubKeyFrom);

    const privateKeyTo = ec.keyFromPrivate(privKeyTo, 'hex');
    const publicKeyFrom = ec.keyFromPublic(pubKeyFrom, 'hex');

    const Px = privateKeyTo.derive(publicKeyFrom.pub).toString('hex');
    const hash = CryptoUtil.sha256(Px);
    if (iv === null) {
      iv = CryptoUtil.sha256(hash).toString('hex').slice(-24);
    }
    return this._aesDecrypt(msg, hash.toString('hex'), iv, note);
  }

  // private functions
  _aesEncrypt(msg, key, iv, note) {
    const aes = new CryptoAESGCM();
    const promise = aes.importKey(key).then( (aes) => {
      return aes.encrypt(msg, note, iv);
    }).then( (encrypted) => {
      return Promise.resolve(encrypted);
    });
    return promise;
  }

  _aesDecrypt(msg, key, iv, note) {
    const aes = new CryptoAESGCM();
    const promise = aes.importKey(key).then( (aes) => {
      return aes.decrypt(msg, iv, note);
    }).then( (decrypted) => {
      return Promise.resolve(decrypted);
    });
    return promise;
  }
}

exports.Util = CryptoUtil;
exports.AESGCM = CryptoAESGCM;
exports.WCrypto = WCrypto;
