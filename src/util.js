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
