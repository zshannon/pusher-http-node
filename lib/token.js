const util = require("./util")

// Helper function to convert string to Uint8Array
function stringToUint8Array(str) {
  return new TextEncoder().encode(str)
}

// Helper function to convert ArrayBuffer to hex string
function arrayBufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

/** Verifies and signs data against the key and secret.
 *
 * @constructor
 * @param {String} key app key
 * @param {String} secret app secret
 */
class Token {
  constructor(key, secret) {
    this.key = key
    this.secret = secret
  }

  /** Signs the string using the secret.
   *
   * @param {String} string
   * @returns {String}
   */
  async sign(string) {
    const key = await crypto.subtle.importKey(
      'raw',
      stringToUint8Array(this.secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    )

    const signature = await crypto.subtle.sign(
      'HMAC',
      key,
      stringToUint8Array(string)
    )

    return arrayBufferToHex(signature)
  }

  /** Checks if the string has correct signature.
   *
   * @param {String} string
   * @param {String} signature
   * @returns {Promise<Boolean>}
   */
  async verify(string, signature) {
    const computedSignature = await this.sign(string)
    return util.secureCompare(computedSignature, signature)
  }
}

module.exports = Token
