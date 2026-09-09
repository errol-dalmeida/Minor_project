import { sha256, signMessage, verifyMessage } from './crypto.js'

export const RevocationReason = {
  NONE: 0,
  KEY_COMPROMISE: 1,
  SUPERSEDED: 2,
  DECOMMISSIONED: 3,
  MALICIOUS_ACTIVITY: 4
}

export const TransactionType = {
  REGISTER_KEY: 'REGISTER_KEY',
  REVOKE_KEY: 'REVOKE_KEY',
  UNREVOKE_KEY: 'UNREVOKE_KEY',
  ROTATE_KEY: 'ROTATE_KEY',
  DATA: 'DATA'
}

/**
 * Cryptographically signed Transaction in the native P2P blockchain
 */
export class Transaction {
  constructor({
    type,
    senderPeerId,
    payload = {},
    nonce = null,
    timestamp = null,
    signature = null
  }) {
    this.type = type
    this.senderPeerId = senderPeerId
    this.payload = payload
    this.nonce = nonce || Math.random().toString(36).substring(2, 12)
    this.timestamp = timestamp || Date.now()
    this.signature = signature
  }

  /**
   * Deterministic SHA-256 hash of the transaction body
   */
  calculateHash() {
    const serialized = JSON.stringify({
      type: this.type,
      senderPeerId: this.senderPeerId,
      payload: this.payload,
      nonce: this.nonce,
      timestamp: this.timestamp
    })
    return sha256(serialized)
  }

  /**
   * Sign transaction hash using sender's private key
   */
  sign(privateKeyHex) {
    const hash = this.calculateHash()
    this.signature = signMessage(hash, privateKeyHex)
    return this.signature
  }

  /**
   * Verify signature against a public key
   */
  verify(publicKeyHex) {
    if (!this.signature) return false
    const hash = this.calculateHash()
    return verifyMessage(hash, this.signature, publicKeyHex)
  }
}

/**
 * Cryptographic Block containing an array of transactions
 */
export class Block {
  constructor({
    index,
    timestamp,
    transactions = [],
    previousHash = '',
    nonce = 0,
    hash = ''
  }) {
    this.index = index
    this.timestamp = timestamp || Date.now()
    this.transactions = transactions.map(tx => tx instanceof Transaction ? tx : new Transaction(tx))
    this.previousHash = previousHash
    this.nonce = nonce
    this.hash = hash || this.calculateHash()
  }

  /**
   * Calculate SHA-256 hash of block contents
   */
  calculateHash() {
    const txHashes = this.transactions.map(tx => tx.calculateHash()).join(':')
    const content = `${this.index}|${this.timestamp}|${this.previousHash}|${txHashes}|${this.nonce}`
    return sha256(content)
  }

  /**
   * Fast Proof-of-Work mining for tamper-evidence
   */
  mine(difficulty = 1) {
    const target = '0'.repeat(difficulty)
    while (!this.hash.startsWith(target)) {
      this.nonce++
      this.hash = this.calculateHash()
    }
    return this.hash
  }
}

/**
 * Native In-Code P2P Blockchain & Decentralized PKI Engine
 */
export class NativeBlockchain {
  constructor(options = {}) {
    this.difficulty = options.difficulty ?? 1
    this.chain = [this.createGenesisBlock()]
    this.mempool = []
    this.state = new Map()         // peerId -> IdentityRecord
    this.keyHistories = new Map()  // peerId -> string[]
    this.listeners = {
      onKeyRegistered: [],
      onKeyRevoked: [],
      onKeyUnrevoked: [],
      onKeyRotated: [],
      onBlockAdded: []
    }
    this.isOnline = true
  }

  /**
   * Create immutable Genesis block
   */
  createGenesisBlock() {
    return new Block({
      index: 0,
      timestamp: 1700000000000,
      transactions: [],
      previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
      nonce: 0,
      hash: '0000000000genesis_block_hash_native_p2p_chain_00000000000000000000'
    })
  }

  getLatestBlock() {
    return this.chain[this.chain.length - 1]
  }

  /**
   * Validate a single transaction against current state
   */
  validateTransaction(tx) {
    if (!tx || !tx.senderPeerId || !tx.type) return { valid: false, error: 'Malformed transaction' }

    const record = this.state.get(tx.senderPeerId)

    if (tx.type === TransactionType.REGISTER_KEY) {
      const { publicKeyHex, didUri } = tx.payload || {}
      if (!publicKeyHex || !didUri) return { valid: false, error: 'Missing public key or DID in payload' }

      if (!record) {
        const ok = tx.verify(publicKeyHex)
        return ok ? { valid: true } : { valid: false, error: 'Invalid initial registration signature' }
      } else {
        if (record.isRevoked) return { valid: false, error: 'Key is revoked. Cannot register with same peer ID.' }
        const ok = tx.verify(record.publicKeyHex)
        return ok ? { valid: true } : { valid: false, error: 'Invalid signature from registered key' }
      }
    }

    if (tx.type === TransactionType.REVOKE_KEY) {
      if (!record) return { valid: false, error: 'Identity not registered' }
      if (record.isRevoked) return { valid: false, error: 'Identity already revoked' }
      const ok = tx.verify(record.publicKeyHex)
      return ok ? { valid: true } : { valid: false, error: 'Invalid signature on revocation' }
    }

    if (tx.type === TransactionType.UNREVOKE_KEY) {
      if (!record) return { valid: false, error: 'Identity not registered' }
      if (!record.isRevoked) return { valid: false, error: 'Identity is not revoked' }
      const ok = tx.verify(record.publicKeyHex)
      return ok ? { valid: true } : { valid: false, error: 'Invalid signature on unrevocation' }
    }

    if (tx.type === TransactionType.ROTATE_KEY) {
      if (!record) return { valid: false, error: 'Identity not registered' }
      if (record.isRevoked) return { valid: false, error: 'Cannot rotate a revoked key' }
      const { newPublicKeyHex, newDidUri } = tx.payload || {}
      if (!newPublicKeyHex || !newDidUri) return { valid: false, error: 'Missing new key or DID' }
      const ok = tx.verify(record.publicKeyHex)
      return ok ? { valid: true } : { valid: false, error: 'Invalid signature for key rotation' }
    }

    return { valid: true }
  }

  /**
   * Apply transaction changes to state
   */
  applyTransactionToState(tx) {
    const { type, senderPeerId, payload, timestamp } = tx

    if (type === TransactionType.REGISTER_KEY) {
      const existing = this.state.get(senderPeerId)
      if (!existing) {
        this.state.set(senderPeerId, {
          peerId: senderPeerId,
          publicKeyHex: payload.publicKeyHex,
          didUri: payload.didUri,
          isRevoked: false,
          reason: RevocationReason.NONE,
          createdAt: timestamp,
          updatedAt: timestamp,
          revokedAt: 0
        })
        const history = this.keyHistories.get(senderPeerId) || []
        history.push(payload.publicKeyHex)
        this.keyHistories.set(senderPeerId, history)

        this.emit('onKeyRegistered', {
          peerId: senderPeerId,
          publicKeyHex: payload.publicKeyHex,
          didUri: payload.didUri,
          timestamp
        })
      } else {
        const oldKey = existing.publicKeyHex
        existing.publicKeyHex = payload.publicKeyHex
        existing.didUri = payload.didUri
        existing.updatedAt = timestamp
        const history = this.keyHistories.get(senderPeerId) || []
        history.push(payload.publicKeyHex)

        this.emit('onKeyRotated', {
          peerId: senderPeerId,
          oldKey,
          newKey: payload.publicKeyHex,
          timestamp
        })
      }
    } else if (type === TransactionType.REVOKE_KEY) {
      const record = this.state.get(senderPeerId)
      if (record) {
        record.isRevoked = true
        record.reason = payload.reason || RevocationReason.KEY_COMPROMISE
        record.revokedAt = timestamp
        record.updatedAt = timestamp

        this.emit('onKeyRevoked', {
          peerId: senderPeerId,
          reason: record.reason,
          timestamp
        })
      }
    } else if (type === TransactionType.UNREVOKE_KEY) {
      const record = this.state.get(senderPeerId)
      if (record) {
        record.isRevoked = false
        record.reason = RevocationReason.NONE
        record.revokedAt = 0
        record.updatedAt = timestamp

        this.emit('onKeyUnrevoked', {
          peerId: senderPeerId,
          timestamp
        })
      }
    } else if (type === TransactionType.ROTATE_KEY) {
      const record = this.state.get(senderPeerId)
      if (record) {
        const oldKey = record.publicKeyHex
        record.publicKeyHex = payload.newPublicKeyHex
        record.didUri = payload.newDidUri
        record.updatedAt = timestamp
        const history = this.keyHistories.get(senderPeerId) || []
        history.push(payload.newPublicKeyHex)

        this.emit('onKeyRotated', {
          peerId: senderPeerId,
          oldKey,
          newKey: payload.newPublicKeyHex,
          timestamp
        })
      }
    }
  }

  /**
   * Submit transaction to mempool and immediately produce a block
   */
  addTransaction(tx) {
    const txObj = tx instanceof Transaction ? tx : new Transaction(tx)
    const check = this.validateTransaction(txObj)
    if (!check.valid) {
      return { success: false, error: check.error }
    }

    this.mempool.push(txObj)
    const block = this.minePendingTransactions()
    return { success: true, txHash: txObj.calculateHash(), block, transaction: txObj }
  }

  /**
   * Mine a block from pending transactions in mempool
   */
  minePendingTransactions() {
    if (this.mempool.length === 0) return null

    const previousBlock = this.getLatestBlock()
    const block = new Block({
      index: previousBlock.index + 1,
      timestamp: Date.now(),
      transactions: [...this.mempool],
      previousHash: previousBlock.hash
    })

    block.mine(this.difficulty)
    this.chain.push(block)
    this.mempool = []

    for (const tx of block.transactions) {
      this.applyTransactionToState(tx)
    }

    this.emit('onBlockAdded', block)
    return block
  }

  addBlock(blockData) {
    const block = blockData instanceof Block ? blockData : new Block(blockData)
    const latest = this.getLatestBlock()

    if (block.index !== latest.index + 1) {
      return { success: false, reason: 'Index mismatch' }
    }
    if (block.previousHash !== latest.hash) {
      return { success: false, reason: 'Previous hash mismatch' }
    }
    if (block.calculateHash() !== block.hash) {
      return { success: false, reason: 'Invalid block hash' }
    }

    for (const tx of block.transactions) {
      const check = this.validateTransaction(tx)
      if (!check.valid) {
        return { success: false, reason: `Invalid transaction in block: ${check.error}` }
      }
    }

    this.chain.push(block)
    for (const tx of block.transactions) {
      this.applyTransactionToState(tx)
    }

    this.emit('onBlockAdded', block)
    return { success: true, block }
  }

  isValidChain(chain) {
    if (!Array.isArray(chain) || chain.length === 0) return false
    const genesis = this.createGenesisBlock()

    if (chain[0].hash !== genesis.hash) return false

    for (let i = 1; i < chain.length; i++) {
      const current = chain[i] instanceof Block ? chain[i] : new Block(chain[i])
      const previous = chain[i - 1] instanceof Block ? chain[i - 1] : new Block(chain[i - 1])

      if (current.previousHash !== previous.hash) return false
      if (current.calculateHash() !== current.hash) return false
    }

    return true
  }

  replaceChain(newChain) {
    if (newChain.length <= this.chain.length) return false
    if (!this.isValidChain(newChain)) return false

    this.chain = newChain.map(b => b instanceof Block ? b : new Block(b))
    this.state.clear()
    this.keyHistories.clear()

    for (let i = 1; i < this.chain.length; i++) {
      for (const tx of this.chain[i].transactions) {
        this.applyTransactionToState(tx)
      }
    }

    return true
  }

  async init() {
    this.isOnline = true
    return true
  }

  async registerKey(peerId, publicKeyHex, didUri, privateKeyHex) {
    const tx = new Transaction({
      type: TransactionType.REGISTER_KEY,
      senderPeerId: peerId,
      payload: { publicKeyHex, didUri }
    })
    tx.sign(privateKeyHex)
    const res = this.addTransaction(tx)
    return { ...res, transaction: tx }
  }

  async revokeKey(peerId, reason = RevocationReason.KEY_COMPROMISE, privateKeyHex) {
    const tx = new Transaction({
      type: TransactionType.REVOKE_KEY,
      senderPeerId: peerId,
      payload: { reason }
    })
    tx.sign(privateKeyHex)
    const res = this.addTransaction(tx)
    return { ...res, transaction: tx }
  }

  async unrevokeKey(peerId, privateKeyHex) {
    const tx = new Transaction({
      type: TransactionType.UNREVOKE_KEY,
      senderPeerId: peerId,
      payload: {}
    })
    tx.sign(privateKeyHex)
    const res = this.addTransaction(tx)
    return { ...res, transaction: tx }
  }

  async rotateKey(peerId, newPublicKeyHex, newDidUri, currentPrivateKeyHex) {
    const tx = new Transaction({
      type: TransactionType.ROTATE_KEY,
      senderPeerId: peerId,
      payload: { newPublicKeyHex, newDidUri }
    })
    tx.sign(currentPrivateKeyHex)
    const res = this.addTransaction(tx)
    return { ...res, transaction: tx }
  }

  async resolveKey(peerId) {
    const record = this.state.get(peerId)
    return record || null
  }

  async verifyKey(peerId, publicKeyHex) {
    const record = this.state.get(peerId)
    if (!record) {
      return { isValid: false, isRevoked: false, status: 'NOT_REGISTERED' }
    }
    if (record.isRevoked) {
      return { isValid: false, isRevoked: true, status: 'REVOKED' }
    }
    const matches = record.publicKeyHex.toLowerCase() === publicKeyHex.toLowerCase()
    return {
      isValid: matches,
      isRevoked: false,
      status: matches ? 'ON_CHAIN_VERIFIED' : 'KEY_MISMATCH'
    }
  }

  getAllRegisteredPeers() {
    return Array.from(this.state.keys())
  }

  getKeyHistory(peerId) {
    return this.keyHistories.get(peerId) || []
  }

  subscribeEvents(handlers = {}) {
    if (handlers.onKeyRegistered) this.listeners.onKeyRegistered.push(handlers.onKeyRegistered)
    if (handlers.onKeyRevoked) this.listeners.onKeyRevoked.push(handlers.onKeyRevoked)
    if (handlers.onKeyUnrevoked) this.listeners.onKeyUnrevoked.push(handlers.onKeyUnrevoked)
    if (handlers.onKeyRotated) this.listeners.onKeyRotated.push(handlers.onKeyRotated)
    if (handlers.onBlockAdded) this.listeners.onBlockAdded.push(handlers.onBlockAdded)
  }

  emit(eventName, data) {
    const list = this.listeners[eventName] || []
    for (const fn of list) {
      try { fn(data) } catch {}
    }
  }
}

export const BlockchainClient = NativeBlockchain
