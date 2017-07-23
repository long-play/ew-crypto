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

  static hexToBase64u(hex) {
    if (!hex) return null;

    const binaryString = CryptoUtil.hexToString(hex);
    const base64 = window.btoa(binaryString);
    return CryptoUtil.base64toBase64u(base64);
  }

  static hexToString(hex) {
    let string = '';
    for (let i = 0; i < hex.length; i += 2) {
      string += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return string;
  }

  static base64toBase64u(base64) {
    let string = base64.replace('+', '-');
    string = string.replace('/', '_');
    return string.replace('=', '');
  }
}
