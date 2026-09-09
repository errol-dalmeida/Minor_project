import crypto, { generateKeyPairSync, createSign, createVerify, createPrivateKey, createPublicKey, diffieHellman, randomBytes, createCipheriv, createDecipheriv, hkdfSync } from 'crypto'

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
 * Compute SHA-256 hash of string or Buffer
 */
export function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex')
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
 * Compute ECDH Shared Secret from local private key and remote public key
 */
export function computeSharedSecret(privateKeyHex, publicKeyHex) {
  const privateKeyObj = createPrivateKey({
    key: Buffer.from(privateKeyHex, 'hex'),
    format: 'der',
    type: 'pkcs8'
  })
  const publicKeyObj = createPublicKey({
    key: Buffer.from(publicKeyHex, 'hex'),
    format: 'der',
    type: 'spki'
  })

  return diffieHellman({
    privateKey: privateKeyObj,
    publicKey: publicKeyObj
  })
}

/**
 * Derive 256-bit AES symmetric key from shared secret using HKDF-SHA256
 */
export function deriveKey(sharedSecret, info = 'p2p-e2ee-session') {
  return hkdfSync('sha256', sharedSecret, '', info, 32)
}

/**
 * End-to-End Encrypt a message using ECIES (ECDH + HKDF + AES-256-GCM)
 * @param {string} plainText Plain text message to encrypt
 * @param {string} recipientPublicKeyHex Recipient's SPKI DER public key in hex
 * @param {string} senderPrivateKeyHex Sender's PKCS#8 DER private key in hex
 * @returns {{ ciphertext: string, iv: string, tag: string }}
 */
export function encryptECC(plainText, recipientPublicKeyHex, senderPrivateKeyHex) {
  const sharedSecret = computeSharedSecret(senderPrivateKeyHex, recipientPublicKeyHex)
  const aesKey = deriveKey(sharedSecret, 'p2p-e2ee-session')

  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', aesKey, iv)

  let ciphertext = cipher.update(plainText, 'utf8', 'hex')
  ciphertext += cipher.final('hex')
  const tag = cipher.getAuthTag().toString('hex')

  return {
    ciphertext,
    iv: iv.toString('hex'),
    tag
  }
}

/**
 * Decrypt an ECIES-encrypted message
 * @param {{ ciphertext: string, iv: string, tag: string }} encryptedData
 * @param {string} senderPublicKeyHex Sender's SPKI DER public key in hex
 * @param {string} recipientPrivateKeyHex Recipient's PKCS#8 DER private key in hex
 * @returns {string} Decrypted plaintext string
 */
export function decryptECC(encryptedData, senderPublicKeyHex, recipientPrivateKeyHex) {
  const { ciphertext, iv, tag } = encryptedData
  const sharedSecret = computeSharedSecret(recipientPrivateKeyHex, senderPublicKeyHex)
  const aesKey = deriveKey(sharedSecret, 'p2p-e2ee-session')

  const decipher = createDecipheriv('aes-256-gcm', aesKey, Buffer.from(iv, 'hex'))
  decipher.setAuthTag(Buffer.from(tag, 'hex'))

  let decrypted = decipher.update(ciphertext, 'hex', 'utf8')
  decrypted += decipher.final('utf8')
  return decrypted
}

/**
 * Generate a random 256-bit symmetric channel key
 */
export function generateChannelKey() {
  return randomBytes(32).toString('hex')
}

/**
 * Encrypt a channel message using symmetric AES-256-GCM
 */
export function encryptChannelMessage(plainText, channelKeyHex) {
  const key = Buffer.from(channelKeyHex, 'hex')
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)

  let ciphertext = cipher.update(plainText, 'utf8', 'hex')
  ciphertext += cipher.final('hex')
  const tag = cipher.getAuthTag().toString('hex')

  return {
    ciphertext,
    iv: iv.toString('hex'),
    tag
  }
}

/**
 * Decrypt a channel message using symmetric AES-256-GCM
 */
export function decryptChannelMessage(encryptedData, channelKeyHex) {
  const { ciphertext, iv, tag } = encryptedData
  const key = Buffer.from(channelKeyHex, 'hex')
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'))
  decipher.setAuthTag(Buffer.from(tag, 'hex'))

  let decrypted = decipher.update(ciphertext, 'hex', 'utf8')
  decrypted += decipher.final('utf8')
  return decrypted
}

/**
 * Construct a timestamped, signed envelope
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