const crypto = require("crypto")

function toOrderedArray(map) {
  return Object.keys(map)
    .map(function (key) {
      return [key, map[key]]
    })
    .sort(function (a, b) {
      if (a[0] < b[0]) {
        return -1
      }
      if (a[0] > b[0]) {
        return 1
      }
      return 0
    })
    .map(function (pair) {
      return pair[0] + "=" + pair[1]
    })
}

function getMD5(body) {
  return crypto.createHash("md5").update(body, "utf8").digest("hex")
}

function secureCompare(a, b) {
  if (a.length !== b.length) {
    return false
  }
  let result = 0
  for (const i in a) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }
  return result === 0
}

function isEncryptedChannel(channel) {
  return channel.startsWith("private-encrypted-")
}

function hexToUint8Array(hexString) {
	// Remove the "0x" prefix if it exists
	hexString = hexString.startsWith('0x') ? hexString.slice(2) : hexString

	// Ensure that the hex string has an even length
	if (hexString.length % 2 !== 0) {
		throw new Error(`Hex string must have an even number of characters: [${hexString}]`)
	}

	const byteArray = new Uint8Array(hexString.length / 2)

	for (let i = 0; i < hexString.length; i += 2) {
		const byte = Number.parseInt(hexString.substr(i, 2), 16)
		byteArray[i / 2] = byte
	}

	return byteArray
}

exports.hexToUint8Array = hexToUint8Array
exports.toOrderedArray = toOrderedArray
exports.getMD5 = getMD5
exports.secureCompare = secureCompare
exports.isEncryptedChannel = isEncryptedChannel
