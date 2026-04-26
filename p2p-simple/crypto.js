import { generateKeyPairSync, createSign, createVerify } from 'crypto'

export function generateKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  })
  return {
    privateKey: privateKey.toString('hex'),
    publicKey:  publicKey.toString('hex')
  }
}

export function createDID(peerId, publicKeyHex) {
  return {
    '@context': 'https://www.w3.org/ns/did/v1',
    id: `did:peer:${peerId}`,
    verificationMethod: [{
      id: `did:peer:${peerId}#key-1`,
      type: 'EcdsaSecp256k1VerificationKey2019',
      controller: `did:peer:${peerId}`,
      publicKeyHex: publicKeyHex
    }]
  }
}

export function signMessage(message, privateKeyHex) {
  const sign = createSign('SHA256')
  sign.update(message)
  sign.end()
  return sign.sign({
    key:    Buffer.from(privateKeyHex, 'hex'),
    format: 'der',
    type:   'pkcs8'
  }, 'hex')
}

export function verifyMessage(message, signatureHex, publicKeyHex) {
  try {
    const verify = createVerify('SHA256')
    verify.update(message)
    verify.end()
    return verify.verify({
      key:    Buffer.from(publicKeyHex, 'hex'),
      format: 'der',
      type:   'spki'
    }, signatureHex, 'hex')
  } catch {
    return false
  }
}