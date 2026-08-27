import { ethers } from 'ethers'
import { readFileSync, existsSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const DEPLOYMENT_PATH = join(__dirname, 'contracts', 'deployedRegistry.json')

export const RevocationReason = {
  NONE: 0,
  KEY_COMPROMISE: 1,
  SUPERSEDED: 2,
  DECOMMISSIONED: 3,
  MALICIOUS_ACTIVITY: 4
}

export class BlockchainClient {
  constructor(options = {}) {
    this.rpcUrl = options.rpcUrl || process.env.RPC_URL || 'http://127.0.0.1:8545'
    this.walletIndex = options.walletIndex ?? (process.env.WALLET_INDEX ? parseInt(process.env.WALLET_INDEX) : 0)
    this.provider = null
    this.signer = null
    this.contract = null
    this.contractAddress = null
    this.isOnline = false
    this.cache = new Map() // peerId -> { publicKeyHex, isRevoked, didUri, owner, reason }
  }

  /**
   * Initialize connection to Ethereum node & load IdentityRegistry contract
   */
  async init() {
    try {
      this.provider = new ethers.JsonRpcProvider(this.rpcUrl)
      
      // Test connectivity
      const network = await this.provider.getNetwork()
      
      const accounts = await this.provider.listAccounts()
      if (accounts.length === 0) {
        throw new Error('No accounts available on local Ethereum node')
      }

      const selectedAccount = accounts[this.walletIndex % accounts.length]
      this.signer = await this.provider.getSigner(selectedAccount.address)

      // Load contract deployment info
      if (!existsSync(DEPLOYMENT_PATH)) {
        console.warn('⚠️  [Blockchain] contracts/deployedRegistry.json not found. Run "npm run deploy" first.')
        return false
      }

      const deployment = JSON.parse(readFileSync(DEPLOYMENT_PATH, 'utf8'))
      this.contractAddress = deployment.address
      this.contract = new ethers.Contract(this.contractAddress, deployment.abi, this.signer)
      this.isOnline = true

      console.log(`⛓️  [Blockchain] Connected to chainId ${network.chainId} (Wallet: ${await this.signer.getAddress()})`)
      console.log(`📜 [Blockchain] IdentityRegistry Contract: ${this.contractAddress}`)
      return true
    } catch (err) {
      console.warn(`⚠️  [Blockchain] Offline or connection error: ${err.message}`)
      this.isOnline = false
      return false
    }
  }

  /**
   * Register or update a peer identity on-chain
   */
  async registerKey(peerId, publicKeyHex, didUri) {
    if (!this.isOnline || !this.contract) {
      console.warn('⚠️  [Blockchain] Not connected. Caching key locally only.')
      this.cache.set(peerId, { publicKeyHex, didUri, isRevoked: false, localOnly: true })
      return { success: false, reason: 'Blockchain offline' }
    }

    try {
      console.log(`⛓️  [Blockchain] Submitting registerKey transaction for ${peerId.slice(0, 16)}...`)
      const tx = await this.contract.registerKey(peerId, publicKeyHex, didUri)
      const receipt = await tx.wait()
      
      this.cache.set(peerId, {
        publicKeyHex,
        didUri,
        isRevoked: false,
        txHash: receipt.hash,
        owner: await this.signer.getAddress()
      })

      console.log(`✅ [Blockchain] Key registered on-chain! Tx: ${receipt.hash.slice(0, 18)}...`)
      return { success: true, txHash: receipt.hash }
    } catch (err) {
      console.error(`❌ [Blockchain] registerKey failed: ${err.message}`)
      return { success: false, error: err.message }
    }
  }

  /**
   * Resolve a peer ID to its active on-chain identity record
   */
  async resolveKey(peerId) {
    if (!this.isOnline || !this.contract) {
      return this.cache.get(peerId) || null
    }

    try {
      const record = await this.contract.resolveKey(peerId)
      const data = {
        owner: record.owner,
        peerId: record.peerId,
        publicKeyHex: record.publicKeyHex,
        didUri: record.didUri,
        isRevoked: Boolean(record.isRevoked),
        reason: Number(record.reason),
        createdAt: Number(record.createdAt),
        updatedAt: Number(record.updatedAt),
        revokedAt: Number(record.revokedAt)
      }
      this.cache.set(peerId, data)
      return data
    } catch (err) {
      // If not registered or query failed
      return null
    }
  }

  /**
   * Fast verification check: is key registered, active, and matching?
   */
  async verifyKey(peerId, publicKeyHex) {
    if (!this.isOnline || !this.contract) {
      const local = this.cache.get(peerId)
      if (!local) return { isValid: false, isRevoked: false, status: 'UNKNOWN' }
      return {
        isValid: local.publicKeyHex === publicKeyHex && !local.isRevoked,
        isRevoked: local.isRevoked,
        status: local.isRevoked ? 'REVOKED' : 'VALID_LOCAL'
      }
    }

    try {
      const [isValid, isRevoked] = await this.contract.isKeyValid(peerId, publicKeyHex)
      return {
        isValid,
        isRevoked,
        status: isRevoked ? 'REVOKED' : (isValid ? 'ON_CHAIN_VERIFIED' : 'KEY_MISMATCH')
      }
    } catch (err) {
      return { isValid: false, isRevoked: false, status: 'NOT_REGISTERED', error: err.message }
    }
  }

  /**
   * Revoke an active key on-chain
   */
  async revokeKey(peerId, reason = RevocationReason.KEY_COMPROMISE) {
    if (!this.isOnline || !this.contract) {
      console.warn('⚠️  [Blockchain] Cannot revoke: Blockchain offline')
      return { success: false, reason: 'Blockchain offline' }
    }

    try {
      console.log(`🚨 [Blockchain] Submitting revokeKey transaction for ${peerId.slice(0, 16)}... (Reason: ${reason})`)
      const tx = await this.contract.revokeKey(peerId, reason)
      const receipt = await tx.wait()

      const cached = this.cache.get(peerId) || {}
      this.cache.set(peerId, { ...cached, isRevoked: true, reason })

      console.log(`🛑 [Blockchain] Key successfully REVOKED on-chain! Tx: ${receipt.hash.slice(0, 18)}...`)
      return { success: true, txHash: receipt.hash }
    } catch (err) {
      console.error(`❌ [Blockchain] revokeKey failed: ${err.message}`)
      return { success: false, error: err.message }
    }
  }

  /**
   * Unrevoke / reinstate an active key on-chain
   */
  async unrevokeKey(peerId) {
    if (!this.isOnline || !this.contract) {
      console.warn('⚠️  [Blockchain] Cannot unrevoke: Blockchain offline')
      return { success: false, reason: 'Blockchain offline' }
    }

    try {
      console.log(`♻️  [Blockchain] Submitting unrevokeKey transaction for ${peerId.slice(0, 16)}...`)
      const tx = await this.contract.unrevokeKey(peerId)
      const receipt = await tx.wait()

      const cached = this.cache.get(peerId) || {}
      this.cache.set(peerId, { ...cached, isRevoked: false, reason: 0 })

      console.log(`✅ [Blockchain] Key UNREVOKED / REINSTATED on-chain! Tx: ${receipt.hash.slice(0, 18)}...`)
      return { success: true, txHash: receipt.hash }
    } catch (err) {
      console.error(`❌ [Blockchain] unrevokeKey failed: ${err.message}`)
      return { success: false, error: err.message }
    }
  }

  /**
   * Rotate to a new public key on-chain
   */
  async rotateKey(peerId, newPublicKeyHex, newDidUri) {
    if (!this.isOnline || !this.contract) {
      return { success: false, reason: 'Blockchain offline' }
    }

    try {
      console.log(`🔄 [Blockchain] Submitting rotateKey transaction for ${peerId.slice(0, 16)}...`)
      const tx = await this.contract.rotateKey(peerId, newPublicKeyHex, newDidUri)
      const receipt = await tx.wait()

      this.cache.set(peerId, {
        publicKeyHex: newPublicKeyHex,
        didUri: newDidUri,
        isRevoked: false,
        txHash: receipt.hash
      })

      console.log(`✅ [Blockchain] Key rotated on-chain! Tx: ${receipt.hash.slice(0, 18)}...`)
      return { success: true, txHash: receipt.hash }
    } catch (err) {
      console.error(`❌ [Blockchain] rotateKey failed: ${err.message}`)
      return { success: false, error: err.message }
    }
  }

  /**
   * Listen to real-time on-chain events via robust block polling
   */
  subscribeEvents(handlers = {}) {
    if (!this.isOnline || !this.contract || !this.provider) return

    let lastBlock = 0
    this.provider.getBlockNumber().then(b => { lastBlock = b }).catch(() => {})

    this.provider.on('block', async (currentBlock) => {
      if (currentBlock <= lastBlock) return
      const fromBlock = lastBlock + 1
      lastBlock = currentBlock

      try {
        if (handlers.onKeyRegistered) {
          const regEvents = await this.contract.queryFilter(this.contract.filters.KeyRegistered(), fromBlock, currentBlock)
          for (const ev of regEvents) {
            const { peerId, owner, publicKeyHex, didUri, timestamp } = ev.args
            this.cache.set(String(peerId), { owner, publicKeyHex, didUri, isRevoked: false })
            handlers.onKeyRegistered({ peerId: String(peerId), owner, publicKeyHex, didUri, timestamp: Number(timestamp) })
          }
        }

        if (handlers.onKeyRevoked) {
          const revEvents = await this.contract.queryFilter(this.contract.filters.KeyRevoked(), fromBlock, currentBlock)
          for (const ev of revEvents) {
            const { peerId, owner, reason, timestamp } = ev.args
            const cached = this.cache.get(String(peerId)) || {}
            this.cache.set(String(peerId), { ...cached, isRevoked: true, reason: Number(reason) })
            handlers.onKeyRevoked({ peerId: String(peerId), owner, reason: Number(reason), timestamp: Number(timestamp) })
          }
        }

        if (handlers.onKeyUnrevoked) {
          const unrevEvents = await this.contract.queryFilter(this.contract.filters.KeyUnrevoked(), fromBlock, currentBlock)
          for (const ev of unrevEvents) {
            const { peerId, owner, timestamp } = ev.args
            const cached = this.cache.get(String(peerId)) || {}
            this.cache.set(String(peerId), { ...cached, isRevoked: false, reason: 0 })
            handlers.onKeyUnrevoked({ peerId: String(peerId), owner, timestamp: Number(timestamp) })
          }
        }

        if (handlers.onKeyRotated) {
          const rotEvents = await this.contract.queryFilter(this.contract.filters.KeyRotated(), fromBlock, currentBlock)
          for (const ev of rotEvents) {
            const { peerId, owner, oldPublicKeyHex, newPublicKeyHex, timestamp } = ev.args
            this.cache.set(String(peerId), { owner, publicKeyHex: newPublicKeyHex, isRevoked: false })
            handlers.onKeyRotated({ peerId: String(peerId), owner, oldKey: oldPublicKeyHex, newKey: newPublicKeyHex, timestamp: Number(timestamp) })
          }
        }
      } catch {}
    })
  }
}
