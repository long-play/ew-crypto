class CryptoUtil {
  constructor() {
  }

  static browser() {
    if (this._browser == null) {
      this._browser = require('detect-browser');
    }
    if (this._browser == null) {
      this._browser = { name: 'unknown' };
    }
    return this._browser;
  }

  static crypto() {
    return window.crypto;
  }

  static subtle() {
    let subtle = null;
    switch(CryptoUtil.browser().name) {
      case 'chrome':
      case 'firefox':
        subtle = window.crypto.subtle;
        break;
      case 'safari':
        subtle = window.crypto.webkitSubtle;
        break;
      default:
        subtle = null;
    }
    return subtle;
  }

  static jwkToBase64(jwk) {
    let key = null;
    switch(CryptoUtil.browser().name) {
      case 'chrome':
      case 'firefox':
        key = CryptoUtil.jsonToBase64(jwk);
        break;
      case 'safari':
        key = CryptoUtil.arrayBufferToBase64(jwk);
        break;
      default:
        key = null;
    }
    return key;
  }

  static base64ToJwk(key) {
    let jwk = null;
    switch(CryptoUtil.browser().name) {
      case 'chrome':
      case 'firefox':
        jwk = CryptoUtil.base64ToJson(key);
        break;
      case 'safari':
        jwk = CryptoUtil.base64ToArrayBuffer(key);
        break;
      default:
        jwk = null;
    }
    return jwk;
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

  static hexToBase64(hex) {
    if (!hex) return null;

    const binaryString = CryptoUtil.hexToString(hex);
    return window.btoa(binaryString);
  }

  static base64ToHex(base64) {
    if (!base64) return null;

    const binaryString = window.atob(base64);
    return CryptoUtil.stringToHex(binaryString);
  }

  static hexToBase64u(hex) {
    if (!hex) return null;

    const base64 = CryptoUtil.hexToBase64(hex);
    return CryptoUtil.base64ToBase64u(base64);
  }

  static hexToString(hex) {
    let string = '';
    for (let i = 0; i < hex.length; i += 2) {
      string += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return string;
  }

  static stringToHex(string) {
    let hex = '';
    for (let i = 0; i < string.length; i++) {
      hex += ('0' + string.charCodeAt(i).toString(16)).slice(-2);
    }
    return hex;
  }

  static base64ToBase64u(base64) {
    let string = base64.replace(/\+/g, '-');
    string = string.replace(/\//g, '_');
    return string.replace(/=/g, '');
  }

  static jsonToBase64(json) {
    const str = JSON.stringify(json);
    return window.btoa(str);
  }

  static base64ToJson(base64) {
    const str = window.atob(base64);
    return JSON.parse(str);
  }
}
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

class CryptoAESGCM {
  constructor() {
  }

  static createKeyFromHex(hexKey) {
    const key = {
      kty: 'oct',
      k: CryptoUtil.hexToBase64u(hexKey),
      alg: 'A256GCM',
      ext: true
    };
    return key;
  }

  generateKeys(length = 256) {
    this.length = length;
    this.iv = CryptoUtil.arrayBufferToBase64(CryptoUtil.crypto().getRandomValues(new Uint8Array(12)));
    const promise = CryptoUtil.subtle().generateKey({
        name: 'AES-GCM',
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

  createKeyFromHex(hexKey) {
    const key = CryptoAESGCM.createKeyFromHex(hexKey);
    this.key = CryptoUtil.jsonToBase64(key);
    this.length = (hexKey.length / 2) * 8;
    this.iv = CryptoUtil.arrayBufferToBase64(CryptoUtil.crypto().getRandomValues(new Uint8Array(12)));

    const keydata = CryptoUtil.base64ToJwk(this.key);
    const promise = CryptoAESGCM._importKey(keydata, ['encrypt', 'decrypt']).then( (pk) => {
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
    const promise = CryptoAESGCM._importKey(keydata, ['encrypt', 'decrypt']).then( (pk) => {
      this.cryptoKey = pk;
      return Promise.resolve(this);
    });
    return promise;
  }

  encrypt(textData, note) {
    const promise = CryptoUtil.subtle().encrypt({
        name: 'AES-GCM',
        iv: CryptoUtil.base64ToArrayBuffer(this.iv),
        additionalData: CryptoUtil.base64ToArrayBuffer(note),
        tagLength: 128
      },
      this.cryptoKey,
      CryptoUtil.stringToArrayBuffer(textData)
    ).then( (encryptedBuffer) => {
      return Promise.resolve(CryptoUtil.arrayBufferToBase64(encryptedBuffer));
    });
    return promise;
  }

  decrypt(encryptedTextData, note) {
    const promise = CryptoUtil.subtle().decrypt({
        name: 'AES-GCM',
        iv: CryptoUtil.base64ToArrayBuffer(this.iv),
        additionalData: CryptoUtil.base64ToArrayBuffer(note),
        tagLength: 128
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
        name: 'AES-GCM'
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

const BN = require('bn.js');
const EC = require('elliptic').ec;
const createHash = require('create-hash');

const ec = new EC('secp256k1');
const ecparams = ec.curve;

class WCrypto {
  constructor() {
  }

  encrypt(msg, privKeyFrom, pubKeyTo) {
    const privateKeyFrom = this._privateKeyCreateFromHex(privKeyFrom);
    const publicKeyFrom = this._getPublicKeyFromPrivate(privKeyFrom);
    const publicKeyTo = this._getPublicKey(pubKeyTo);

    const Px = this._derive(publicKeyTo, privateKeyFrom);
    const hash = this._sha256(Px);
    const encrypted = this._aesEncrypt(msg, hash.toString('hex'));
    //const encrypted = 'aes256gcm.encrypt(iv, hash, msg)';
    return encrypted;
  }

  decrypt(msg, privKeyTo, pubKeyFrom, iv) {
    const privateKeyTo = this._privateKeyCreateFromHex(privKeyTo);
    const publicKeyTo = this._getPublicKeyFromPrivate(privKeyTo);
    const publicKeyFrom = this._getPublicKey(pubKeyFrom);

    const Px = this._derive(publicKeyFrom, privateKeyTo);
    const hash = this._sha256(Px);
    const decrypted = this._aesDecrypt(msg, hash.toString('hex'), iv);
    //const decrypted = 'aes256gcm.decrypt(iv, hash, msg)';
    return decrypted;
  }

  // private functions
  _aesEncrypt(msg, key) {
    const aes = new CryptoAESCBC();
    const promise = aes.createKeyFromHex(key).then( (aes) => {
      console.log('key: ' + aes.key);
      console.log('iv: ' + aes.iv);
      return aes.encrypt(msg);
    }).then( (encrypted) => {
      console.log('encr: ' + encrypted);
      return Promise.resolve({ encrypted: encrypted, iv: aes.iv });
    });
    return promise;
  }

  _aesDecrypt(msg, key, iv) {
    const aes = new CryptoAESCBC();
    const hexIV = CryptoUtil.base64ToHex(iv);
    const promise = aes.createKeyFromHex(key, hexIV).then( (aes) => {
      console.log('key: ' + aes.key);
      console.log('iv: ' + aes.iv);
      return aes.decrypt(msg);
    }).then( (decrypted) => {
      console.log('decr: ' + decrypted);
      return Promise.resolve(decrypted);
    });
    return promise;
  }

  _getPublicKey(pubKey) {
    //assert(privKey.length === 32, "Bad private key");
    // See https://github.com/wanderer/secp256k1-node/issues/46
    var compressed = this._publicKeyCreateFromHex(pubKey);
    return this._publicKeyConvert(compressed, false);
  }

  _getPublicKeyFromPrivate(privKey) {
    //assert(privKey.length === 32, "Bad private key");
    // See https://github.com/wanderer/secp256k1-node/issues/46
    var compressed = this._publicKeyCreateFromPrivate(privKey);
    return this._publicKeyConvert(compressed, false);
  }

  _derive(pubA, privB) {
    return this._ecdh(pubA, privB);
  }

  _sha256(msg) {
    return createHash('sha256').update(msg).digest();
  }

  _sha512(msg) {
    return createHash('sha512').update(msg).digest();
  }

  // secp256k1
  _privateKeyCreateFromHex(privKey) {
    //const d = new BN(privKey)
    //if (d.cmp(ecparams.n) >= 0 || d.isZero()) throw new Error(messages.EC_PUBLIC_KEY_CREATE_FAIL)

    //const priv = ec.keyFromPrivate(privKey, 'hex').getPrivate();
    return Buffer.from(privKey, 'hex'); //ec.keyFromPrivate(privKey).getPrivate())
  }

  _publicKeyCreateFromHex(pubKey, compressed) {
    //const d = new BN(privKey)
    //if (d.cmp(ecparams.n) >= 0 || d.isZero()) throw new Error(messages.EC_PUBLIC_KEY_CREATE_FAIL)

    return Buffer.from(ec.keyFromPublic(pubKey, 'hex').getPublic(compressed, true))
  }

  _publicKeyCreateFromPrivate(privKey, compressed) {
    //const d = new BN(privKey)
    //if (d.cmp(ecparams.n) >= 0 || d.isZero()) throw new Error(messages.EC_PUBLIC_KEY_CREATE_FAIL)

    return Buffer.from(ec.keyFromPrivate(privKey).getPublic(compressed, true))
  }

  _publicKeyConvert(pubKey, compressed) {
    const pair = this._loadPublicKey(pubKey)
    if (pair === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)

    return Buffer.from(pair.getPublic(compressed, true))
  }

  _loadPublicKey(pubKey) {
    const first = pubKey[0]
    switch (first) {
      case 0x02:
      case 0x03:
        if (pubKey.length !== 33) return null
        return this._loadCompressedPublicKey(first, pubKey.slice(1, 33))
      case 0x04:
      case 0x06:
      case 0x07:
        if (pubKey.length !== 65) return null
        return this._loadUncompressedPublicKey(first, pubKey.slice(1, 33), pubKey.slice(33, 65))
      default:
        return null
    }
  }

  _loadCompressedPublicKey (first, xBuffer) {
    let x = new BN(xBuffer)

    // overflow
    if (x.cmp(ecparams.p) >= 0) return null
    x = x.toRed(ecparams.red)

    // compute corresponding Y
    const y = x.redSqr().redIMul(x).redIAdd(ecparams.b).redSqrt()
    if ((first === 0x03) !== y.isOdd()) y = y.redNeg()

    return ec.keyPair({ pub: { x: x, y: y } })
  }

  _loadUncompressedPublicKey (first, xBuffer, yBuffer) {
    let x = new BN(xBuffer)
    let y = new BN(yBuffer)

    // overflow
    if (x.cmp(ecparams.p) >= 0 || y.cmp(ecparams.p) >= 0) return null

    x = x.toRed(ecparams.red)
    y = y.toRed(ecparams.red)

    // is odd flag
    if ((first === 0x06 || first === 0x07) && y.isOdd() !== (first === 0x07)) return null

    // x*x*x + b = y*y
    const x3 = x.redSqr().redIMul(x)
    if (!y.redSqr().redISub(x3.redIAdd(ecparams.b)).isZero()) return null

    return ec.keyPair({ pub: { x: x, y: y } })
  }

  _ecdh (publicKey, privateKey) {
    var shared = this._ecdhUnsafe(publicKey, privateKey, true)
    return this._sha256(shared);
  }

  _ecdhUnsafe (publicKey, privateKey, compressed) {
    var pair = this._loadPublicKey(publicKey)
    //if (pair === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)

    var scalar = new BN(privateKey)
    //if (scalar.cmp(ecparams.n) >= 0 || scalar.isZero()) throw new Error(messages.ECDH_FAIL)

    return Buffer.from(pair.pub.mul(scalar).encode(true, compressed))
  }
}
exports.AESCBC = CryptoAESCBC;
exports.AESGCM = CryptoAESGCM;
exports.RSA = CryptoRSA;
exports.Util = CryptoUtil;
exports.WCrypto = WCrypto;
