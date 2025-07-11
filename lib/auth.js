const secp256k1 = require("@noble/secp256k1")
const util = require("./util")

// Helper function to convert string to Uint8Array
function stringToUint8Array(str) {
  return new TextEncoder().encode(str)
}

// Helper function to convert Uint8Array to hex string
function uint8ArrayToHex(uint8Array) {
  return Array.from(uint8Array)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

// Helper function to generate random bytes using Web Crypto API
function getRandomBytes(length) {
  const array = new Uint8Array(length)
  crypto.getRandomValues(array)
  return array
}

// Helper function to hash data using Web Crypto API
async function sha256(data) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return new Uint8Array(hashBuffer)
}

// Helper function to parse DER signature and extract raw 64-byte signature
function parseDERSignature(derSignature) {
  // DER format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
  let offset = 0

  // Check DER sequence tag (0x30)
  if (derSignature[offset] !== 0x30) {
    throw new Error('Invalid DER signature: missing sequence tag')
  }
  offset += 1

  // Skip total length
  const totalLength = derSignature[offset]
  offset += 1

  // Parse R value
  if (derSignature[offset] !== 0x02) {
    throw new Error('Invalid DER signature: missing R integer tag')
  }
  offset += 1

  const rLength = derSignature[offset]
  offset += 1

  let rValue = derSignature.slice(offset, offset + rLength)
  offset += rLength

  // Parse S value
  if (derSignature[offset] !== 0x02) {
    throw new Error('Invalid DER signature: missing S integer tag')
  }
  offset += 1

  const sLength = derSignature[offset]
  offset += 1

  let sValue = derSignature.slice(offset, offset + sLength)

  // Remove leading zeros and pad to 32 bytes
  while (rValue.length > 1 && rValue[0] === 0x00) {
    rValue = rValue.slice(1)
  }
  while (sValue.length > 1 && sValue[0] === 0x00) {
    sValue = sValue.slice(1)
  }

  // Pad to 32 bytes
  const r = new Uint8Array(32)
  const s = new Uint8Array(32)

  r.set(rValue, 32 - rValue.length)
  s.set(sValue, 32 - sValue.length)

  // Concatenate r and s for 64-byte signature
  const rawSignature = new Uint8Array(64)
  rawSignature.set(r, 0)
  rawSignature.set(s, 32)

  return rawSignature
}

async function getSocketSignatureForUser(token, socketId, userData) {
  const ts = Date.now()
  const privKey = util.hexToUint8Array(token.secret)
  const publicKey = secp256k1.getPublicKey(privKey, false)
  const publicKeyHex = uint8ArrayToHex(publicKey)

  const user_data = JSON.stringify(userData)
  const stringToSign = `${socketId}:${ts}::user::${user_data}`
  const digest = await sha256(stringToUint8Array(stringToSign))

  // NB: here's a deviation from the Pusher docs, which say to use the SECRET key to do HMAC-SHA256 digest
  //     but we're stateless so we need to do verifiable ecdsa signatures instead
  const derSignature = await secp256k1.sign(digest, privKey, {
    extraEntropy: true,
  })
  const rawSignature = parseDERSignature(derSignature)

  return {
    auth: `${publicKeyHex}:${ts}:${uint8ArrayToHex(rawSignature)}`,
    user_data,
  }
}

async function getSocketSignature(pusher, token, channel, socketID, data) {
  const ts = Date.now()
  const privKey = util.hexToUint8Array(token.secret)
  const stringToSign = `${socketID}:${ts}:${channel}`
  const digest = await sha256(stringToUint8Array(stringToSign))

  // NB: here's a deviation from the Pusher docs, which say to use the SECRET key to do HMAC-SHA256 digest
  //     but we're stateless so we need to do verifiable ecdsa signatures instead
  const derSignature = await secp256k1.sign(digest, privKey, {
    extraEntropy: true,
  })
  const rawSignature = parseDERSignature(derSignature)

  return {
    auth: `${token.key}:${ts}:${uint8ArrayToHex(rawSignature)}`,
  }
}

exports.getSocketSignatureForUser = getSocketSignatureForUser
exports.getSocketSignature = getSocketSignature
