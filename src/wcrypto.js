const BN = require('bn.js');
const EC = require('elliptic').ec;
const createHash = require('create-hash');

const ec = new EC('secp256k1');
const ecparams = ec.curve;

class WCrypto {
  constructor() {
  }

  encrypt(msg, privKeyFrom, pubKeyTo, note) {
    privKeyFrom = CryptoUtil.trimHex(privKeyFrom);
    pubKeyTo = CryptoUtil.trimHex(pubKeyTo);

    const privateKeyFrom = this._privateKeyCreateFromHex(privKeyFrom);
    const publicKeyFrom = this._getPublicKeyFromPrivate(privKeyFrom);
    const publicKeyTo = this._getPublicKey(pubKeyTo);

    const Px = this._derive(publicKeyTo, privateKeyFrom);
    const hash = this._sha256(Px);
    return this._aesEncrypt(msg, hash.toString('hex'), note);
  }

  decrypt(msg, privKeyTo, pubKeyFrom, iv, note) {
    privKeyTo = CryptoUtil.trimHex(privKeyTo);
    pubKeyFrom = CryptoUtil.trimHex(pubKeyFrom);

    const privateKeyTo = this._privateKeyCreateFromHex(privKeyTo);
    const publicKeyTo = this._getPublicKeyFromPrivate(privKeyTo);
    const publicKeyFrom = this._getPublicKey(pubKeyFrom);

    const Px = this._derive(publicKeyFrom, privateKeyTo);
    const hash = this._sha256(Px);
    return this._aesDecrypt(msg, hash.toString('hex'), iv, note);
  }

  // private functions
  _aesEncrypt(msg, key, note) {
    const aes = new CryptoAESGCM();
    const promise = aes.importKey(key).then( (aes) => {
      return aes.encrypt(msg, note);
    }).then( (encrypted) => {
      console.log('enc: ' + JSON.stringify(encrypted));
      return Promise.resolve(encrypted);
    });
    return promise;
  }

  _aesDecrypt(msg, key, iv, note) {
    const aes = new CryptoAESGCM();
    const promise = aes.importKey(key).then( (aes) => {
      return aes.decrypt(msg, iv, note);
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
