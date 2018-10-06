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
