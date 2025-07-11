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

async function getSHA256(body) {
  const data = typeof body === 'string' ? stringToUint8Array(body) : body
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return arrayBufferToHex(hashBuffer)
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
exports.getSHA256 = getSHA256
exports.secureCompare = secureCompare
exports.isEncryptedChannel = isEncryptedChannel
