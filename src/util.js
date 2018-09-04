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
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
  }

  static hexToBuffer(hex) {
    return new Uint8Array(CryptoUtil.trimHex(hex).match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  }

  static trimHex(hex) {
    if (hex.slice(0, 2) == '0x') hex = hex.slice(2);
    return hex;
  }
}
