const Buffer = require("buffer").Buffer
const crypto = require("crypto")
const secp256k1 = require("secp256k1")

const util = require("./util")

function getSocketSignatureForUser(token, socketId, userData) {
  const privKey = util.hexToUint8Array(token.secret)
  const user_data = JSON.stringify(userData)
  const stringToSign = `${socketId}::user::${user_data}`
  const digest = crypto.createHash('sha256').update(Buffer.from(stringToSign)).digest()
  // NB: here's a deviation from the Pusher docs, which say to use the SECRET key to do HMAC-SHA256 digest
  //     but we're stateless so we need to do verifiable ecdsa signatures instead
  const sigObject = secp256k1.ecdsaSign(new Uint8Array(digest), privKey, {
    noncefn: () => crypto.randomBytes(32),
  })
  return {
    auth: `${publicKey}:${Buffer.from(sigObject.signature).toString('hex')}`,
    user_data,
  }
}

function getSocketSignature(pusher, token, channel, socketID, data) {
  const privKey = util.hexToUint8Array(token.secret)
  const stringToSign = `${socketID}:${channel}`
  const digest = crypto.createHash('sha256').update(Buffer.from(stringToSign)).digest()
  // NB: here's a deviation from the Pusher docs, which say to use the SECRET key to do HMAC-SHA256 digest
  //     but we're stateless so we need to do verifiable ecdsa signatures instead
  const sigObject = secp256k1.ecdsaSign(new Uint8Array(digest), privKey, {
    noncefn: () => crypto.randomBytes(32),
  })
  return { auth: `${token.key}:${Buffer.from(sigObject.signature).toString('hex')}` }
}

exports.getSocketSignatureForUser = getSocketSignatureForUser
exports.getSocketSignature = getSocketSignature
