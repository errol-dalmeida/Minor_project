import { createLibp2p } from 'libp2p'
import { tcp } from '@libp2p/tcp'
import { mplex } from '@libp2p/mplex'
import { noise } from '@chainsafe/libp2p-noise'
import { bootstrap } from '@libp2p/bootstrap'
import { mdns } from '@libp2p/mdns'
import { fromString, toString } from 'uint8arrays'
import { generateKeyPair, createDID, signMessage, verifyMessage } from './crypto.js'
import { BlockchainClient, RevocationReason } from './blockchain.js'
import * as readline from 'readline'
import { writeFileSync } from 'fs'

// ── PASTE RELAY ADDRESS HERE ──────────────────────────────────────
const BOOTSTRAP_ADDR = process.env.RELAY_ADDR || '/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWDrVXBueH62aGpGxdeYU8AJFUT6n38xfmNMRXydtk682S'
// ─────────────────────────────────────────────────────────────────

const RELAY_ID = BOOTSTRAP_ADDR.includes('/p2p/') ? BOOTSTRAP_ADDR.split('/p2p/')[1] : ''

// Step 1: Generate ECDSA keypair + DID for this peer
let { privateKey, publicKey } = generateKeyPair()

// Step 2: In-memory network state & trust database
const trustScores   = new Map() // peerId → score (0-100)
const keyRegistry   = new Map() // peerId → publicKeyHex
const peers         = new Set() // active connected peer IDs
const lastSeen      = new Map() // peerId → timestamp
const revokedPeers  = new Set() // peerIds revoked on-chain

// Step 3: Initialize Blockchain Client (DPKI)
const walletIndexArg = process.argv[2] ? parseInt(process.argv[2]) : (process.env.WALLET_INDEX ? parseInt(process.env.WALLET_INDEX) : 0)
const blockchain = new BlockchainClient({
  walletIndex: walletIndexArg,
  rpcUrl: process.env.RPC_URL || 'http://127.0.0.1:8545'
})

const node = await createLibp2p({
  addresses: { listen: ['/ip4/0.0.0.0/tcp/0'] },
  transports: [tcp()],
  streamMuxers: [mplex()],
  connectionEncryption: [noise()],
  peerDiscovery: [
    bootstrap({ list: [BOOTSTRAP_ADDR] }),
    mdns()
  ]
})

const MY_ID  = node.peerId.toString()
let MY_DID = createDID(MY_ID, publicKey)

writeFileSync(
  `did-${MY_ID.slice(0, 8)}.json`,
  JSON.stringify(MY_DID, null, 2)
)
console.log(`📄 DID saved to: did-${MY_ID.slice(0, 8)}.json`)

// Step 4: Connect to Blockchain & Register Key
const bcConnected = await blockchain.init()
if (bcConnected) {
  console.log(`⛓️  [DPKI] Auto-registering identity on-chain for ${MY_ID.slice(0, 16)}...`)
  await blockchain.registerKey(MY_ID, publicKey, MY_DID.id)

  // Listen to on-chain real-time revocation and rotation events
  blockchain.subscribeEvents({
    onKeyRevoked: ({ peerId, reason }) => {
      const pid = String(peerId)
      revokedPeers.add(pid)
      trustScores.set(pid, 0)
      console.log(`\n🚨 [BLOCKCHAIN EVENT] Peer ${pid.slice(0,16)}... was REVOKED on-chain! (Reason: ${reason})`)
      console.log(`   Trust set to 0. Subsequent messages will be discarded.`)
    },
    onKeyUnrevoked: ({ peerId }) => {
      const pid = String(peerId)
      revokedPeers.delete(pid)
      trustScores.set(pid, 50)
      console.log(`\n♻️  [BLOCKCHAIN EVENT] Peer ${pid.slice(0,16)}... key was UNREVOKED / REINSTATED on-chain!`)
      console.log(`   Trust restored to 50/100.`)
    },
    onKeyRotated: ({ peerId, newKey }) => {
      const pid = String(peerId)
      keyRegistry.set(pid, newKey)
      revokedPeers.delete(pid)
      console.log(`\n🔄 [BLOCKCHAIN EVENT] Peer ${pid.slice(0,16)}... rotated public key on-chain!`)
    },
    onKeyRegistered: ({ peerId, publicKeyHex }) => {
      const pid = String(peerId)
      keyRegistry.set(pid, publicKeyHex)
      if (!trustScores.has(pid)) trustScores.set(pid, 50)
      console.log(`\n🆔 [BLOCKCHAIN EVENT] Peer ${pid.slice(0,16)}... registered key on-chain.`)
    }
  })
} else {
  console.log('⚠️  [DPKI] Running in standalone/offline mode (Blockchain not connected).')
}

// ── Protocol 1: DID announcement ────────────────────────────────
node.handle('/did/1.0.0', async ({ stream, connection }) => {
  const sender = connection.remotePeer.toString()
  for await (const chunk of stream.source) {
    try {
      const { peerId, did, publicKey: theirKey } = JSON.parse(toString(chunk.subarray()))
      keyRegistry.set(peerId, theirKey)

      // Query Blockchain for canonical verification
      const onChainRecord = await blockchain.resolveKey(peerId)
      if (onChainRecord && onChainRecord.isRevoked) {
        revokedPeers.add(peerId)
        trustScores.set(peerId, 0)
        console.log(`\n🚨 [DPKI] Received DID from ${peerId.slice(0,16)}... but key is REVOKED on-chain!`)
      } else if (!trustScores.has(peerId)) {
        trustScores.set(peerId, 50)
        console.log(`\n🆔 DID received from: ${peerId.slice(0,16)}...`)
        console.log(`   DID   : ${did.id}`)
        console.log(`   Status: ${onChainRecord ? '✅ On-Chain Registered' : '⚠️  Unregistered On-Chain'}`)
        console.log(`   Trust : 50/100`)
      }
    } catch {}
  }
})

// ── Protocol 2: Signed chat messages with Blockchain DPKI Verification ──
node.handle('/chat/1.0.0', async ({ stream, connection }) => {
  const sender = connection.remotePeer.toString()
  for await (const chunk of stream.source) {
    try {
      const { message, signature } = JSON.parse(toString(chunk.subarray()))

      // 1. Check On-Chain Revocation Status
      const onChainCheck = await blockchain.verifyKey(sender, keyRegistry.get(sender) || '')

      if (onChainCheck.isRevoked || revokedPeers.has(sender)) {
        trustScores.set(sender, 0)
        console.log(`\n🚫 [BLOCKED - REVOKED KEY] Message from ${sender.slice(0,16)}... REJECTED:`)
        console.log(`   Key has been cryptographically revoked on-chain!`)
        console.log(`   Trust: 0/100 (Quarantined)`)
        continue
      }

      // 2. Resolve Public Key (Prefer On-Chain canonical key, fallback to gossip)
      let senderKey = keyRegistry.get(sender)
      if (onChainCheck.isValid) {
        const onChainData = await blockchain.resolveKey(sender)
        if (onChainData?.publicKeyHex) senderKey = onChainData.publicKeyHex
      }

      if (!senderKey) {
        console.log(`\n⚠️  Message from ${sender.slice(0,16)}... — no DID or public key found`)
        continue
      }

      // 3. Verify Digital Signature
      const valid   = verifyMessage(message, signature, senderKey)
      const current = trustScores.get(sender) ?? 50
      lastSeen.set(sender, Date.now())

      if (valid) {
        const bonus = onChainCheck.isValid ? 5 : 2
        const next  = Math.min(100, current + bonus)
        trustScores.set(sender, next)
        const tag = onChainCheck.isValid ? '✅ ON-CHAIN VERIFIED' : '⚠️  GOSSIP VERIFIED'
        console.log(`\n📩 [${tag}] ${sender.slice(0,16)}...: ${message}`)
        console.log(`   Trust: ${current} → ${next}`)
      } else {
        const next = Math.max(0, current - 25)
        trustScores.set(sender, next)
        console.log(`\n📩 [❌ BAD SIGNATURE] ${sender.slice(0,16)}...: signature verification failed!`)
        console.log(`   Trust: ${current} → ${next}`)
      }
    } catch {}
  }
})

await node.start()

console.log('\n✅ Peer started successfully')
console.log('Peer ID :', MY_ID)
console.log('DID     :', MY_DID.id)
console.log('PubKey  :', publicKey.slice(0, 24) + '...')
console.log('Relay   :', BOOTSTRAP_ADDR)
console.log('\nCommands:')
console.log('  <message>           - Send signed message to all connected peers')
console.log('  register            - Register current key on the blockchain')
console.log('  revoke [reason]     - Revoke current key on-chain (1:Compromised, 2:Superseded, 3:Decommissioned)')
console.log('  rotate              - Generate new keypair and rotate on-chain')
console.log('  lookup <peerId>     - Query peer status and key history from blockchain')
console.log('  trust               - Show trust scores and on-chain verification badges')
console.log('  peers               - Show connected peer list')
console.log('  status              - Show node & blockchain status')
console.log('  Ctrl+C              - Exit\n')

// Step 5: Announce our DID to newly connected peers
async function announceDID(peerId) {
  try {
    const stream  = await node.dialProtocol(peerId, '/did/1.0.0')
    const payload = JSON.stringify({ peerId: MY_ID, did: MY_DID, publicKey })
    await stream.sink([fromString(payload)])
  } catch {}
}

async function broadcastDID() {
  const connections = node.getConnections()
  const peerConns   = connections.filter(c => c.remotePeer.toString() !== RELAY_ID)
  const payload     = JSON.stringify({ peerId: MY_ID, did: MY_DID, publicKey })
  const seen        = new Set()

  for (const conn of peerConns) {
    const id = conn.remotePeer.toString()
    if (seen.has(id)) continue
    seen.add(id)
    try {
      const stream = await node.dialProtocol(conn.remotePeer, '/did/1.0.0')
      await stream.sink([fromString(payload)])
    } catch {}
  }
}

node.addEventListener('peer:connect', async (e) => {
  const id = e.detail.toString()
  if (id === RELAY_ID) { console.log('🔗 Connected to relay'); return }
  peers.add(id)
  lastSeen.set(id, Date.now())
  console.log(`\n🔗 Peer joined: ${id.slice(0,16)}... (${peers.size} peer(s) connected)`)
  setTimeout(() => announceDID(e.detail), 500)
})

node.addEventListener('peer:disconnect', (e) => {
  const id = e.detail.toString()
  if (id === RELAY_ID) return
  peers.delete(id)
  console.log(`\n🔌 Peer left: ${id.slice(0,16)}... (${peers.size} peer(s) remaining)`)
})

node.addEventListener('peer:discovery', async (evt) => {
  const peerId = evt.detail.id
  const id = peerId.toString()
  if (id === MY_ID || id === RELAY_ID) return
  try { await node.dial(peerId) } catch {}
})

// Step 6: Sign and send message to all peers
async function sendToAll(message) {
  const connections = node.getConnections()
  const peerConns   = connections.filter(c => c.remotePeer.toString() !== RELAY_ID)

  if (peerConns.length === 0) {
    console.log('⚠️  No peers connected yet')
    return
  }

  const signature = signMessage(message, privateKey)
  const payload   = JSON.stringify({ message, signature })
  const seen      = new Set()
  let sent        = 0

  for (const conn of peerConns) {
    const id = conn.remotePeer.toString()
    if (seen.has(id)) continue
    if (revokedPeers.has(id)) {
      console.log(`🚫 [QUARANTINE] Skipping transmission to revoked peer ${id.slice(0,16)}...`)
      continue
    }
    seen.add(id)
    try {
      const stream = await node.dialProtocol(conn.remotePeer, '/chat/1.0.0')
      await stream.sink([fromString(payload)])
      sent++
    } catch {}
  }
  console.log(`📤 Broadcasted signed message to ${sent} peer(s)`)
}

async function printTrustScores() {
  console.log('\n📊 Trust & Identity Scores:')
  if (trustScores.size === 0) { console.log('   (no peer interactions yet)\n'); return }
  
  for (const [peerIdRaw, score] of trustScores.entries()) {
    const peerId = String(peerIdRaw)
    const bar   = '█'.repeat(Math.floor(score / 10))
    const empty = '░'.repeat(10 - Math.floor(score / 10))
    
    let statusBadge = '⚠️ UNREGISTERED'
    if (revokedPeers.has(peerId)) {
      statusBadge = '🛑 REVOKED'
    } else {
      const onChain = await blockchain.resolveKey(peerId)
      if (onChain && !onChain.isRevoked) {
        statusBadge = '✅ ON-CHAIN'
      } else if (onChain && onChain.isRevoked) {
        statusBadge = '🛑 REVOKED'
      }
    }
    
    console.log(`   ${peerId.slice(0,16)}... [${bar}${empty}] ${score}/100 | ${statusBadge}`)
  }
  console.log()
}

function printPeers() {
  console.log(`\n👥 Connected peers: ${peers.size}`)
  peers.forEach(id => console.log(`   ${id.slice(0,16)}...`))
  console.log()
}

function printStatus() {
  console.log('\n📡 Node & DPKI Status:')
  console.log(`   Peer ID     : ${MY_ID}`)
  console.log(`   DID         : ${MY_DID.id}`)
  console.log(`   PubKey      : ${publicKey.slice(0, 32)}...`)
  console.log(`   Blockchain  : ${blockchain.isOnline ? '🟢 Connected' : '🔴 Offline'}`)
  if (blockchain.contractAddress) {
    console.log(`   Contract    : ${blockchain.contractAddress}`)
  }
  console.log(`   Connected P2P: ${peers.size} peer(s)`)
  console.log()
}

// Uptime bonus for active peers
function applyUptimeBonus() {
  const now = Date.now()
  trustScores.forEach((score, peerId) => {
    if (revokedPeers.has(peerId)) return
    const seen = lastSeen.get(peerId)
    if (seen && now - seen < 60_000) {
      const next = Math.min(100, score + 1)
      trustScores.set(peerId, next)
    }
  })
}

setInterval(applyUptimeBonus, 30_000)

// Step 7: Interactive CLI
const rl = readline.createInterface({ input: process.stdin })
rl.on('line', async (line) => {
  const input = line.trim()
  if (!input) return

  if (input === 'trust') {
    await printTrustScores()
  } else if (input === 'peers') {
    printPeers()
  } else if (input === 'status') {
    printStatus()
  } else if (input === 'register') {
    const res = await blockchain.registerKey(MY_ID, publicKey, MY_DID.id)
    if (res.success) {
      console.log(`✅ Registered on-chain: ${MY_ID.slice(0, 16)}...`)
    }
  } else if (input.startsWith('lookup')) {
    const target = input.split(' ')[1]
    if (!target) {
      console.log('Usage: lookup <peerId>')
      return
    }
    console.log(`🔍 Querying on-chain identity for ${target}...`)
    const rec = await blockchain.resolveKey(target)
    if (!rec) {
      console.log('   ❌ No record found on blockchain.')
    } else {
      console.log('   📄 On-Chain Record:')
      console.log(`      Owner Address : ${rec.owner}`)
      console.log(`      DID URI       : ${rec.didUri}`)
      console.log(`      Public Key    : ${rec.publicKeyHex.slice(0, 32)}...`)
      console.log(`      Status        : ${rec.isRevoked ? '🛑 REVOKED' : '✅ ACTIVE'}`)
      if (rec.isRevoked) console.log(`      Reason Code   : ${rec.reason}`)
      console.log(`      Registered At : ${new Date(rec.createdAt * 1000).toLocaleString()}`)
      console.log(`      Updated At    : ${new Date(rec.updatedAt * 1000).toLocaleString()}`)
    }
  } else if (input === 'revoke' || input.startsWith('revoke ')) {
    const parts = input.trim().split(/\s+/)
    let reasonCode = RevocationReason.KEY_COMPROMISE // Default: 1 (Key Compromised)
    if (parts.length > 1) {
      const arg = parts[1].toLowerCase()
      if (arg === 'compromise' || arg === 'compromised' || arg === '1') reasonCode = 1
      else if (arg === 'superseded' || arg === 'supersede' || arg === '2') reasonCode = 2
      else if (arg === 'decommissioned' || arg === 'decommission' || arg === '3') reasonCode = 3
      else if (arg === 'malicious' || arg === '4') reasonCode = 4
      else {
        const parsed = parseInt(arg, 10)
        if (!isNaN(parsed) && parsed >= 1 && parsed <= 4) reasonCode = parsed
      }
    }
    const res = await blockchain.revokeKey(MY_ID, reasonCode)
    if (res.success) {
      revokedPeers.add(MY_ID)
      console.log(`🛑 Local key has been marked REVOKED on-chain!`)
    }
  } else if (input === 'unrevoke') {
    const res = await blockchain.unrevokeKey(MY_ID)
    if (res.success) {
      revokedPeers.delete(MY_ID)
      console.log(`♻️  Local key has been UNREVOKED and reinstated on-chain!`)
    }
  } else if (input === 'rotate') {
    if (revokedPeers.has(MY_ID)) {
      console.log('❌ Cannot rotate: This key is already REVOKED on-chain. A compromised identity cannot be rotated.')
      return
    }

    console.log('🔄 Generating new ECDSA keypair...')
    const newKeypair = generateKeyPair()
    const newDID = createDID(MY_ID, newKeypair.publicKey)
    
    const res = await blockchain.rotateKey(MY_ID, newKeypair.publicKey, newDID.id)
    if (res.success) {
      privateKey = newKeypair.privateKey
      publicKey  = newKeypair.publicKey
      MY_DID     = newDID
      writeFileSync(`did-${MY_ID.slice(0, 8)}.json`, JSON.stringify(MY_DID, null, 2))
      console.log(`✅ Key rotated successfully! New PubKey: ${publicKey.slice(0, 24)}...`)
      
      // Re-announce new key to connected peers
      await broadcastDID()
    } else {
      console.log(`❌ Key rotation failed: ${res.error || res.reason}`)
    }
  } else {
    await sendToAll(input)
  }
})