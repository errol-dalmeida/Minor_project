import { generateKeyPairSync, createSign, createVerify } from 'crypto'

/**
 * Generate a new ECDSA keypair (NIST P-256 / prime256v1 curve)
 * Returned as DER hexadecimal strings for SPKI (public) and PKCS#8 (private)
 */
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

/**
 * Construct a W3C-compliant Decentralized Identifier (DID) Document
 */
export function createDID(peerId, publicKeyHex) {
  return {
    '@context': 'https://www.w3.org/ns/did/v1',
    id: `did:peer:${peerId}`,
    verificationMethod: [{
      id: `did:peer:${peerId}#key-1`,
      type: 'EcdsaSecp256r1VerificationKey2020',
      controller: `did:peer:${peerId}`,
      publicKeyHex: publicKeyHex
    }]
  }
}

/**
 * Sign a string payload using ECDSA SHA-256
 */
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

/**
 * Verify an ECDSA SHA-256 signature against a public key
 */
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

/**
 * Construct a timestamped and nonced message envelope with signature
 */
export function createMessageEnvelope(text, senderPeerId, privateKeyHex) {
  const payload = {
    sender: senderPeerId,
    timestamp: Date.now(),
    nonce: Math.random().toString(36).substring(2, 15),
    text: text
  }
  const serialized = JSON.stringify(payload)
  const signature = signMessage(serialized, privateKeyHex)
  return {
    payload,
    signature
  }
}