import { createLibp2p } from 'libp2p'
import { tcp } from '@libp2p/tcp'
import { mplex } from '@libp2p/mplex'
import { noise } from '@chainsafe/libp2p-noise'
import { bootstrap } from '@libp2p/bootstrap'
import { mdns } from '@libp2p/mdns'
import { fromString, toString } from 'uint8arrays'
import {
  generateKeyPair,
  createDID,
  signMessage,
  verifyMessage,
  encryptECC,
  decryptECC,
  generateChannelKey,
  encryptChannelMessage,
  decryptChannelMessage,
  sha256
} from './crypto.js'
import { NativeBlockchain, Transaction, TransactionType, RevocationReason } from './blockchain.js'
import * as readline from 'readline'
import { writeFileSync } from 'fs'

// ── RELAY ADDRESS ────────────────────────────────────────────────
const BOOTSTRAP_ADDR = process.env.RELAY_ADDR || '/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWDrVXBueH62aGpGxdeYU8AJFUT6n38xfmNMRXydtk682S'
const RELAY_ID = BOOTSTRAP_ADDR.includes('/p2p/') ? BOOTSTRAP_ADDR.split('/p2p/')[1] : ''

// Step 1: Generate ECDSA keypair + DID for this peer
let { privateKey, publicKey } = generateKeyPair()

// Step 2: In-memory network state & trust database
const trustScores     = new Map() // peerId → score (0-100)
const keyRegistry     = new Map() // peerId → publicKeyHex
const peers           = new Set() // active connected peer IDs
const lastSeen        = new Map() // peerId → timestamp
const revokedPeers    = new Set() // peerIds revoked on-chain

// Channels State
const joinedChannels  = new Set(['#general'])
const channelKeys     = new Map([['#general', sha256('public-general-channel-salt')]])
const channelMembers  = new Map([['#general', new Set()]])
let activeChannel     = '#general'

// Step 3: Initialize Native In-Code P2P Blockchain
const blockchain = new NativeBlockchain()

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

// Register own key on native blockchain
console.log(`⛓️  [Native Blockchain] Registering genesis identity for ${MY_ID.slice(0, 16)}...`)
const regResult = await blockchain.registerKey(MY_ID, publicKey, MY_DID.id, privateKey)
if (regResult.success) {
  console.log(`✅ [Blockchain] Identity registered in Block #${regResult.block.index}! Hash: ${regResult.block.hash.slice(0, 18)}...`)
}

// Subscribe to internal blockchain events
blockchain.subscribeEvents({
  onKeyRevoked: ({ peerId, reason }) => {
    const pid = String(peerId)
    revokedPeers.add(pid)
    trustScores.set(pid, 0)
    console.log(`\n🚨 [BLOCKCHAIN EVENT] Peer ${pid.slice(0, 16)}... was REVOKED on-chain! (Reason code: ${reason})`)
    console.log(`   Trust set to 0. All subsequent communications quarantined.`)
  },
  onKeyUnrevoked: ({ peerId }) => {
    const pid = String(peerId)
    revokedPeers.delete(pid)
    trustScores.set(pid, 50)
    console.log(`\n♻️  [BLOCKCHAIN EVENT] Peer ${pid.slice(0, 16)}... was REINSTATED on-chain!`)
    console.log(`   Trust restored to 50/100.`)
  },
  onKeyRotated: ({ peerId, newKey }) => {
    const pid = String(peerId)
    keyRegistry.set(pid, newKey)
    revokedPeers.delete(pid)
    console.log(`\n🔄 [BLOCKCHAIN EVENT] Peer ${pid.slice(0, 16)}... rotated public key on-chain!`)
  },
  onKeyRegistered: ({ peerId, publicKeyHex }) => {
    const pid = String(peerId)
    keyRegistry.set(pid, publicKeyHex)
    if (!trustScores.has(pid)) trustScores.set(pid, 50)
    console.log(`\n🆔 [BLOCKCHAIN EVENT] Peer ${pid.slice(0, 16)}... registered key on-chain.`)
  }
})

// ────────────────────────────────────────────────────────────────
// Blockchain P2P Synchronization Protocols
// ────────────────────────────────────────────────────────────────

// 1. Transaction Gossip Protocol (Register, Revoke, Unrevoke, Rotate)
node.handle('/chain/tx/1.0.0', async ({ stream, connection }) => {
  for await (const chunk of stream.source) {
    try {
      const txData = JSON.parse(toString(chunk.subarray()))
      const tx = new Transaction(txData)
      const res = blockchain.addTransaction(tx)
      if (res.success) {
        console.log(`⛓️  [Blockchain] Processed on-chain transaction [${tx.type}] from ${tx.senderPeerId.slice(0, 16)}...`)
      }
    } catch {}
  }
})

// 2. Full Chain Synchronization Protocol
node.handle('/chain/sync/1.0.0', async ({ stream, connection }) => {
  for await (const chunk of stream.source) {
    try {
      const msg = JSON.parse(toString(chunk.subarray()))
      if (msg.type === 'GET_CHAIN') {
        const response = JSON.stringify({
          type: 'CHAIN_RESPONSE',
          chain: blockchain.chain
        })
        await stream.sink([fromString(response)])
      } else if (msg.type === 'CHAIN_RESPONSE') {
        if (Array.isArray(msg.chain) && msg.chain.length > blockchain.chain.length) {
          const replaced = blockchain.replaceChain(msg.chain)
          if (replaced) {
            console.log(`⛓️  [Blockchain Sync] Synchronized ${msg.chain.length} blocks from ${connection.remotePeer.toString().slice(0, 16)}...`)
          }
        }
      }
    } catch {}
  }
})

// ────────────────────────────────────────────────────────────────
// Communication Protocols
// ────────────────────────────────────────────────────────────────

// Protocol 1: DID Announcement & Real-Time Identity Registration
node.handle('/did/1.0.0', async ({ stream, connection }) => {
  const sender = connection.remotePeer.toString()
  for await (const chunk of stream.source) {
    try {
      const { peerId, did, publicKey: theirKey, regTx } = JSON.parse(toString(chunk.subarray()))
      keyRegistry.set(peerId, theirKey)

      if (regTx) {
        blockchain.addTransaction(new Transaction(regTx))
      } else if (!blockchain.state.has(peerId)) {
        blockchain.state.set(peerId, {
          peerId,
          publicKeyHex: theirKey,
          didUri: did?.id || `did:peer:${peerId}`,
          isRevoked: false,
          reason: RevocationReason.NONE,
          createdAt: Date.now(),
          updatedAt: Date.now(),
          revokedAt: 0
        })
      }

      const onChainRecord = await blockchain.resolveKey(peerId)
      if (onChainRecord && onChainRecord.isRevoked) {
        revokedPeers.add(peerId)
        trustScores.set(peerId, 0)
        console.log(`\n🚨 [DPKI] Received DID from ${peerId.slice(0, 16)}... but key is REVOKED on-chain!`)
      } else if (!trustScores.has(peerId)) {
        trustScores.set(peerId, 50)
        console.log(`\n🆔 DID received from: ${peerId.slice(0, 16)}...`)
        console.log(`   DID   : ${did.id}`)
        console.log(`   Status: ${onChainRecord ? '✅ On-Chain Registered' : '⚠️  Unregistered On-Chain'}`)
        console.log(`   Trust : 50/100`)
      }
    } catch {}
  }
})

// Protocol 2: 1-on-1 End-to-End Encrypted Direct Message (ECIES)
node.handle('/chat/dm/1.0.0', async ({ stream, connection }) => {
  const sender = connection.remotePeer.toString()
  for await (const chunk of stream.source) {
    try {
      const { from, to, encryptedData, signature, timestamp } = JSON.parse(toString(chunk.subarray()))
      if (to !== MY_ID) continue

      // 1. Check On-Chain Revocation Status
      const onChainCheck = await blockchain.verifyKey(from, keyRegistry.get(from) || '')
      if (onChainCheck.isRevoked || revokedPeers.has(from)) {
        trustScores.set(from, 0)
        console.log(`\n🚫 [BLOCKED DM - REVOKED KEY] Direct message from ${from.slice(0, 16)}... REJECTED.`)
        continue
      }

      // 2. Resolve sender public key
      let senderKey = keyRegistry.get(from)
      const onChainData = await blockchain.resolveKey(from)
      if (onChainData?.publicKeyHex) senderKey = onChainData.publicKeyHex

      if (!senderKey) {
        console.log(`\n⚠️  [DM] Direct message from ${from.slice(0, 16)}... discarded (unknown public key).`)
        continue
      }

      // 3. Verify Signature over Ciphertext
      const sigPayload = `${encryptedData.ciphertext}:${encryptedData.iv}:${encryptedData.tag}:${timestamp}`
      const validSig = verifyMessage(sigPayload, signature, senderKey)

      if (!validSig) {
        const current = trustScores.get(from) ?? 50
        const next = Math.max(0, current - 25)
        trustScores.set(from, next)
        console.log(`\n❌ [DM - BAD SIGNATURE] Direct message from ${from.slice(0, 16)}... failed signature check!`)
        continue
      }

      // 4. Decrypt with Asymmetric ECC (ECIES)
      let decryptedText
      try {
        decryptedText = decryptECC(encryptedData, senderKey, privateKey)
      } catch (err) {
        console.log(`\n❌ [DM - DECRYPTION FAILED] Could not decrypt message from ${from.slice(0, 16)}...`)
        continue
      }

      // 5. Update trust score
      const current = trustScores.get(from) ?? 50
      const next = Math.min(100, current + 5)
      trustScores.set(from, next)
      lastSeen.set(from, Date.now())

      console.log(`\n🔒 [CONFIDENTIAL 1-on-1 DM] from ${from.slice(0, 16)}...:`)
      console.log(`   💬 "${decryptedText}"`)
      console.log(`   🔐 ECIES Decrypted | ✅ On-Chain Verified (Trust: ${current} → ${next})`)
    } catch {}
  }
})

// Protocol 3: Custom Group Channel Messages
node.handle('/chat/channel/1.0.0', async ({ stream, connection }) => {
  const sender = connection.remotePeer.toString()
  for await (const chunk of stream.source) {
    try {
      const { channel, from, encryptedData, signature, timestamp } = JSON.parse(toString(chunk.subarray()))
      
      if (!joinedChannels.has(channel)) continue

      // 1. Check On-Chain Revocation Status
      const onChainCheck = await blockchain.verifyKey(from, keyRegistry.get(from) || '')
      if (onChainCheck.isRevoked || revokedPeers.has(from)) {
        trustScores.set(from, 0)
        console.log(`\n🚫 [BLOCKED CHANNEL - REVOKED KEY] Message in ${channel} from ${from.slice(0, 16)}... REJECTED.`)
        continue
      }

      // 2. Resolve sender public key
      let senderKey = keyRegistry.get(from)
      const onChainData = await blockchain.resolveKey(from)
      if (onChainData?.publicKeyHex) senderKey = onChainData.publicKeyHex

      if (!senderKey) continue

      // 3. Verify Signature
      const sigPayload = `${channel}:${encryptedData.ciphertext}:${encryptedData.iv}:${encryptedData.tag}:${timestamp}`
      const validSig = verifyMessage(sigPayload, signature, senderKey)
      if (!validSig) {
        const current = trustScores.get(from) ?? 50
        trustScores.set(from, Math.max(0, current - 25))
        console.log(`\n❌ [${channel} - BAD SIGNATURE] Message from ${from.slice(0, 16)}... signature invalid!`)
        continue
      }

      // 4. Decrypt Channel Message
      const channelKey = channelKeys.get(channel)
      if (!channelKey) continue

      let decryptedText
      try {
        decryptedText = decryptChannelMessage(encryptedData, channelKey)
      } catch (err) {
        console.log(`\n❌ [${channel}] Decryption failed for message from ${from.slice(0, 16)}...`)
        continue
      }

      const current = trustScores.get(from) ?? 50
      const next = Math.min(100, current + 3)
      trustScores.set(from, next)
      lastSeen.set(from, Date.now())

      console.log(`\n📢 [CHANNEL ${channel}] ${from.slice(0, 16)}...:`)
      console.log(`   💬 "${decryptedText}"`)
      console.log(`   🔐 Channel Encrypted | ✅ Verified (Trust: ${current} → ${next})`)
    } catch {}
  }
})

// Protocol 4: Channel Join / Membership Announcement
node.handle('/channel/join/1.0.0', async ({ stream, connection }) => {
  for await (const chunk of stream.source) {
    try {
      const { peerId, channel, action } = JSON.parse(toString(chunk.subarray()))
      if (!channelMembers.has(channel)) {
        channelMembers.set(channel, new Set())
      }
      const members = channelMembers.get(channel)
      if (action === 'JOIN') {
        members.add(peerId)
        console.log(`\n👥 [Channel ${channel}] Peer ${peerId.slice(0, 16)}... joined channel. (${members.size} members)`)
      } else if (action === 'LEAVE') {
        members.delete(peerId)
        console.log(`\n👥 [Channel ${channel}] Peer ${peerId.slice(0, 16)}... left channel.`)
      }
    } catch {}
  }
})

// Protocol 5: Public Broadcast Chat
node.handle('/chat/1.0.0', async ({ stream, connection }) => {
  const sender = connection.remotePeer.toString()
  for await (const chunk of stream.source) {
    try {
      const { message, signature } = JSON.parse(toString(chunk.subarray()))

      // 1. Check On-Chain Revocation Status
      const onChainCheck = await blockchain.verifyKey(sender, keyRegistry.get(sender) || '')
      if (onChainCheck.isRevoked || revokedPeers.has(sender)) {
        trustScores.set(sender, 0)
        console.log(`\n🚫 [BLOCKED BROADCAST] Message from ${sender.slice(0, 16)}... REJECTED (Revoked Key).`)
        continue
      }

      // 2. Resolve Public Key
      let senderKey = keyRegistry.get(sender)
      if (onChainCheck.isValid) {
        const onChainData = await blockchain.resolveKey(sender)
        if (onChainData?.publicKeyHex) senderKey = onChainData.publicKeyHex
      }

      if (!senderKey) {
        console.log(`\n⚠️  Broadcast from ${sender.slice(0, 16)}... — no public key registered.`)
        continue
      }

      // 3. Verify Signature
      const valid = verifyMessage(message, signature, senderKey)
      const current = trustScores.get(sender) ?? 50
      lastSeen.set(sender, Date.now())

      if (valid) {
        const next = Math.min(100, current + 2)
        trustScores.set(sender, next)
        console.log(`\n📢 [BROADCAST] ${sender.slice(0, 16)}...: ${message}`)
        console.log(`   Trust: ${current} → ${next} | ✅ Verified`)
      } else {
        const next = Math.max(0, current - 25)
        trustScores.set(sender, next)
        console.log(`\n📢 [❌ BAD SIGNATURE] Broadcast from ${sender.slice(0, 16)}... failed signature check!`)
      }
    } catch {}
  }
})

await node.start()

console.log('\n================================================================')
console.log(' 🚀 P2P NODE STARTED (Native Blockchain + ECC Asymmetric Crypto)')
console.log('================================================================')
console.log('Peer ID        :', MY_ID)
console.log('DID            :', MY_DID.id)
console.log('Public Key     :', publicKey.slice(0, 32) + '...')
console.log('Active Channel :', activeChannel)
console.log('Joined Channels:', Array.from(joinedChannels).join(', '))
console.log('Relay Bootstrap:', BOOTSTRAP_ADDR)
console.log('\nCommands:')
console.log('  @<peerId> <msg>     - Send End-to-End Encrypted (ECIES) Direct Message')
console.log('  #<channel> <msg>    - Send Encrypted Message to specific Group Channel')
console.log('  <message>           - Send message to active channel (' + activeChannel + ')')
console.log('  join <#channel>     - Join/Create a custom group channel')
console.log('  leave <#channel>    - Leave a group channel')
console.log('  channels            - List joined channels & member counts')
console.log('  register            - Register/update identity on native blockchain')
console.log('  revoke [reason]     - Revoke current key on-chain (1:Compromised, 2:Superseded, 3:Decommissioned, 4:Malicious)')
console.log('  unrevoke            - Reinstate revoked key on-chain')
console.log('  rotate              - Generate new keypair and rotate on-chain')
console.log('  lookup <peerId>     - Query blockchain record & key history')
console.log('  blocks / chain      - View local blockchain height & block details')
console.log('  trust               - Show trust scores and verification badges')
console.log('  peers               - Show connected peer list')
console.log('  status              - Show node, DPKI, and channel status')
console.log('  Ctrl+C              - Exit\n')

// ────────────────────────────────────────────────────────────────
// Helper Functions for P2P Transmission (With Peer Deduplication)
// ────────────────────────────────────────────────────────────────

async function announceDID(peerId) {
  try {
    const stream  = await node.dialProtocol(peerId, '/did/1.0.0')
    const tx = new Transaction({
      type: TransactionType.REGISTER_KEY,
      senderPeerId: MY_ID,
      payload: { publicKeyHex: publicKey, didUri: MY_DID.id }
    })
    tx.sign(privateKey)
    const payload = JSON.stringify({ peerId: MY_ID, did: MY_DID, publicKey, regTx: tx })
    await stream.sink([fromString(payload)])
  } catch {}
}

async function syncBlockchainWithPeer(peerId) {
  try {
    const stream = await node.dialProtocol(peerId, '/chain/sync/1.0.0')
    const payload = JSON.stringify({ type: 'GET_CHAIN' })
    await stream.sink([fromString(payload)])
  } catch {}
}

async function broadcastTransaction(tx) {
  const connections = node.getConnections().filter(c => c.remotePeer.toString() !== RELAY_ID)
  const payload = JSON.stringify(tx)
  const seen = new Set()
  for (const conn of connections) {
    const id = conn.remotePeer.toString()
    if (seen.has(id)) continue
    seen.add(id)
    try {
      const stream = await node.dialProtocol(conn.remotePeer, '/chain/tx/1.0.0')
      await stream.sink([fromString(payload)])
    } catch {}
  }
}

async function announceChannelAction(channel, action = 'JOIN') {
  const connections = node.getConnections().filter(c => c.remotePeer.toString() !== RELAY_ID)
  const payload = JSON.stringify({ peerId: MY_ID, channel, action })
  const seen = new Set()
  for (const conn of connections) {
    const id = conn.remotePeer.toString()
    if (seen.has(id)) continue
    seen.add(id)
    try {
      const stream = await node.dialProtocol(conn.remotePeer, '/channel/join/1.0.0')
      await stream.sink([fromString(payload)])
    } catch {}
  }
}

// 1. Send E2EE Direct Message (ECIES)
async function sendDirectMessage(recipientPeerId, messageText) {
  let targetKey = keyRegistry.get(recipientPeerId)
  const onChainRecord = await blockchain.resolveKey(recipientPeerId)

  if (onChainRecord?.publicKeyHex) {
    targetKey = onChainRecord.publicKeyHex
  }

  if (!targetKey) {
    console.log(`❌ Cannot send DM: Recipient ${recipientPeerId.slice(0, 16)}... public key not found on blockchain or gossip.`)
    return
  }

  if (onChainRecord && onChainRecord.isRevoked) {
    console.log(`🚫 Cannot send DM: Recipient ${recipientPeerId.slice(0, 16)}... has a REVOKED key on-chain!`)
    return
  }

  // 1. Asymmetric ECIES Encryption
  const encryptedData = encryptECC(messageText, targetKey, privateKey)
  const timestamp = Date.now()

  // 2. ECDSA Signature over Ciphertext Envelope
  const sigPayload = `${encryptedData.ciphertext}:${encryptedData.iv}:${encryptedData.tag}:${timestamp}`
  const signature = signMessage(sigPayload, privateKey)

  const payload = JSON.stringify({
    from: MY_ID,
    to: recipientPeerId,
    encryptedData,
    signature,
    timestamp
  })

  const conn = node.getConnections().find(c => c.remotePeer.toString() === recipientPeerId)
  if (!conn) {
    console.log(`⚠️  Peer ${recipientPeerId.slice(0, 16)}... is not directly connected.`)
    return
  }

  try {
    const stream = await node.dialProtocol(conn.remotePeer, '/chat/dm/1.0.0')
    await stream.sink([fromString(payload)])
    console.log(`🔒 [DM SENT] Encrypted with ECIES (ECC) & signed for ${recipientPeerId.slice(0, 16)}...`)
    console.log(`   💬 "${messageText}"`)
  } catch (err) {
    console.log(`❌ Failed to deliver DM: ${err.message}`)
  }
}

// 2. Send Group Channel Message
async function sendChannelMessage(channel, messageText) {
  if (!joinedChannels.has(channel)) {
    console.log(`❌ You have not joined ${channel}. Type "join ${channel}" first.`)
    return
  }

  let channelKey = channelKeys.get(channel)
  if (!channelKey) {
    channelKey = sha256(`channel-key-salt-${channel}`)
    channelKeys.set(channel, channelKey)
  }

  // 1. Encrypt with Channel Key
  const encryptedData = encryptChannelMessage(messageText, channelKey)
  const timestamp = Date.now()

  // 2. ECDSA Signature
  const sigPayload = `${channel}:${encryptedData.ciphertext}:${encryptedData.iv}:${encryptedData.tag}:${timestamp}`
  const signature = signMessage(sigPayload, privateKey)

  const payload = JSON.stringify({
    channel,
    from: MY_ID,
    encryptedData,
    signature,
    timestamp
  })

  const connections = node.getConnections().filter(c => c.remotePeer.toString() !== RELAY_ID)
  const seen = new Set()
  let sent = 0

  for (const conn of connections) {
    const id = conn.remotePeer.toString()
    if (seen.has(id)) continue
    seen.add(id)
    if (revokedPeers.has(id)) continue
    try {
      const stream = await node.dialProtocol(conn.remotePeer, '/chat/channel/1.0.0')
      await stream.sink([fromString(payload)])
      sent++
    } catch {}
  }
  console.log(`📢 [CHANNEL ${channel}] Sent encrypted message to ${sent} peer(s): "${messageText}"`)
}

// 3. Send Broadcast Message
async function sendBroadcast(messageText) {
  const connections = node.getConnections().filter(c => c.remotePeer.toString() !== RELAY_ID)
  const seen = new Set()
  let sent = 0

  const signature = signMessage(messageText, privateKey)
  const payload = JSON.stringify({ message: messageText, signature })

  for (const conn of connections) {
    const id = conn.remotePeer.toString()
    if (seen.has(id)) continue
    seen.add(id)
    if (revokedPeers.has(id)) continue
    try {
      const stream = await node.dialProtocol(conn.remotePeer, '/chat/1.0.0')
      await stream.sink([fromString(payload)])
      sent++
    } catch {}
  }
  console.log(`📤 Broadcasted signed message to ${sent} peer(s)`)
}

// ────────────────────────────────────────────────────────────────
// Event Listeners for Peer Connectivity
// ────────────────────────────────────────────────────────────────

node.addEventListener('peer:connect', async (e) => {
  const id = e.detail.toString()
  if (id === RELAY_ID) { console.log('🔗 Connected to relay'); return }
  peers.add(id)
  lastSeen.set(id, Date.now())
  console.log(`\n🔗 Peer joined: ${id.slice(0, 16)}... (${peers.size} peer(s) connected)`)

  setTimeout(() => announceDID(e.detail), 400)
  setTimeout(() => {
    for (const ch of joinedChannels) {
      announceChannelAction(ch, 'JOIN').catch(() => {})
    }
  }, 600)
  setTimeout(() => syncBlockchainWithPeer(e.detail), 800)
})

node.addEventListener('peer:disconnect', (e) => {
  const id = e.detail.toString()
  if (id === RELAY_ID) return
  peers.delete(id)
  channelMembers.forEach(members => members.delete(id))
  console.log(`\n🔌 Peer left: ${id.slice(0, 16)}... (${peers.size} peer(s) remaining)`)
})

node.addEventListener('peer:discovery', async (evt) => {
  const peerId = evt.detail.id
  const id = peerId.toString()
  if (id === MY_ID || id === RELAY_ID) return
  try { await node.dial(peerId) } catch {}
})

// ────────────────────────────────────────────────────────────────
// Diagnostic CLI Commands
// ────────────────────────────────────────────────────────────────

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
        statusBadge = '✅ ON-CHAIN VERIFIED'
      } else if (onChain && onChain.isRevoked) {
        statusBadge = '🛑 REVOKED'
      }
    }
    console.log(`   ${peerId.slice(0, 16)}... [${bar}${empty}] ${score}/100 | ${statusBadge}`)
  }
  console.log()
}

function printChannels() {
  console.log('\n📡 Group Channels:')
  console.log(`   Active Target Channel : ${activeChannel}`)
  console.log(`   Joined Channels       : ${Array.from(joinedChannels).join(', ')}`)
  console.log('\n👥 Channel Member Counts:')
  for (const [ch, members] of channelMembers.entries()) {
    console.log(`   ${ch.padEnd(12)}: ${members.size + (joinedChannels.has(ch) ? 1 : 0)} member(s)`)
  }
  console.log()
}

function printBlocks() {
  console.log(`\n⛓️  Native Blockchain State (Height: ${blockchain.chain.length} blocks):`)
  blockchain.chain.forEach(b => {
    console.log(`   [Block #${b.index}] Hash: ${b.hash.slice(0, 18)}... | Prev: ${b.previousHash.slice(0, 12)}... | Txs: ${b.transactions.length} | Nonce: ${b.nonce}`)
    b.transactions.forEach((tx, idx) => {
      console.log(`      └─ Tx #${idx + 1}: [${tx.type}] Sender: ${tx.senderPeerId.slice(0, 14)}...`)
    })
  })
  console.log()
}

function printStatus() {
  console.log('\n📡 Node, DPKI & Crypto Status:')
  console.log(`   Peer ID     : ${MY_ID}`)
  console.log(`   DID         : ${MY_DID.id}`)
  console.log(`   Public Key  : ${publicKey.slice(0, 32)}... (ECDSA prime256v1)`)
  console.log(`   E2EE Crypto : ECIES (ECDH + HKDF-SHA256 + AES-256-GCM)`)
  console.log(`   Blockchain  : 🟢 Native In-Code P2P Chain (Height: ${blockchain.chain.length})`)
  console.log(`   Registered  : ${blockchain.getAllRegisteredPeers().length} peer identities`)
  console.log(`   Active Chan : ${activeChannel}`)
  console.log(`   Connected   : ${peers.size} peer(s)`)
  console.log()
}

// ────────────────────────────────────────────────────────────────
// Interactive CLI Input Loop
// ────────────────────────────────────────────────────────────────

const rl = readline.createInterface({ input: process.stdin })

rl.on('line', async (line) => {
  const input = line.trim()
  if (!input) return

  // 1. Direct 1-on-1 Message: @peerId <message> or dm <peerId> <message>
  if (input.startsWith('@') || input.startsWith('dm ')) {
    let target = ''
    let msg = ''

    if (input.startsWith('@')) {
      const parts = input.slice(1).split(' ')
      target = parts[0]
      msg = parts.slice(1).join(' ')
    } else {
      const parts = input.split(' ')
      target = parts[1]
      msg = parts.slice(2).join(' ')
    }

    if (!target || !msg) {
      console.log('Usage: @<peerId> <message> or dm <peerId> <message>')
      return
    }

    const fullPeerId = Array.from(peers).find(p => p.startsWith(target)) ||
                       Array.from(keyRegistry.keys()).find(p => p.startsWith(target)) ||
                       target

    await sendDirectMessage(fullPeerId, msg)
    return
  }

  // 2. Channel Message: #channel <message>
  if (input.startsWith('#')) {
    const parts = input.split(' ')
    const ch = parts[0]
    const msg = parts.slice(1).join(' ')
    if (!msg) {
      activeChannel = ch
      if (!joinedChannels.has(ch)) {
        joinedChannels.add(ch)
        channelKeys.set(ch, sha256(`channel-key-salt-${ch}`))
        await announceChannelAction(ch, 'JOIN')
      }
      console.log(`🎯 Switched active target channel to: ${activeChannel}`)
      return
    }
    await sendChannelMessage(ch, msg)
    return
  }

  // 3. Join Channel: join #channel
  if (input.startsWith('join ')) {
    let ch = input.split(' ')[1]
    if (!ch.startsWith('#')) ch = '#' + ch
    joinedChannels.add(ch)
    if (!channelKeys.has(ch)) {
      channelKeys.set(ch, sha256(`channel-key-salt-${ch}`))
    }
    activeChannel = ch
    await announceChannelAction(ch, 'JOIN')
    console.log(`✅ Joined group channel: ${ch} (Set as active target)`)
    return
  }

  // 4. Leave Channel: leave #channel
  if (input.startsWith('leave ')) {
    let ch = input.split(' ')[1]
    if (!ch.startsWith('#')) ch = '#' + ch
    if (ch === '#general') {
      console.log('Cannot leave default #general channel.')
      return
    }
    joinedChannels.delete(ch)
    await announceChannelAction(ch, 'LEAVE')
    if (activeChannel === ch) activeChannel = '#general'
    console.log(`👋 Left group channel: ${ch}`)
    return
  }

  // 5. Blockchain & Diagnostic Commands
  if (input === 'channels') {
    printChannels()
  } else if (input === 'blocks' || input === 'chain') {
    printBlocks()
  } else if (input === 'trust') {
    await printTrustScores()
  } else if (input === 'peers') {
    console.log(`\n👥 Connected peers: ${peers.size}`)
    peers.forEach(id => console.log(`   ${id.slice(0, 16)}...`))
    console.log()
  } else if (input === 'status') {
    printStatus()
  } else if (input === 'register') {
    const res = await blockchain.registerKey(MY_ID, publicKey, MY_DID.id, privateKey)
    if (res.success) {
      await broadcastTransaction(res.transaction)
      console.log(`✅ Key registered on native blockchain in Block #${res.block.index}! Broadcasted to network.`)
    }
  } else if (input === 'revoke' || input.startsWith('revoke ')) {
    const parts = input.trim().split(/\s+/)
    let reasonCode = RevocationReason.KEY_COMPROMISE
    if (parts.length > 1) {
      const arg = parts[1].toLowerCase()
      if (arg === 'compromise' || arg === '1') reasonCode = 1
      else if (arg === 'superseded' || arg === '2') reasonCode = 2
      else if (arg === 'decommissioned' || arg === '3') reasonCode = 3
      else if (arg === 'malicious' || arg === '4') reasonCode = 4
      else {
        const parsed = parseInt(arg, 10)
        if (!isNaN(parsed) && parsed >= 1 && parsed <= 4) reasonCode = parsed
      }
    }
    const res = await blockchain.revokeKey(MY_ID, reasonCode, privateKey)
    if (res.success) {
      revokedPeers.add(MY_ID)
      await broadcastTransaction(res.transaction)
      console.log(`🛑 Key marked REVOKED on native blockchain! Broadcasted to network. Reason code: ${reasonCode}`)
    }
  } else if (input === 'unrevoke') {
    const res = await blockchain.unrevokeKey(MY_ID, privateKey)
    if (res.success) {
      revokedPeers.delete(MY_ID)
      await broadcastTransaction(res.transaction)
      console.log(`♻️  Key UNREVOKED & REINSTATED on native blockchain! Broadcasted to network.`)
    }
  } else if (input === 'rotate') {
    if (revokedPeers.has(MY_ID)) {
      console.log('❌ Cannot rotate: This identity is REVOKED on-chain.')
      return
    }

    console.log('🔄 Generating new ECDSA keypair...')
    const newKeypair = generateKeyPair()
    const newDID = createDID(MY_ID, newKeypair.publicKey)

    const res = await blockchain.rotateKey(MY_ID, newKeypair.publicKey, newDID.id, privateKey)
    if (res.success) {
      privateKey = newKeypair.privateKey
      publicKey  = newKeypair.publicKey
      MY_DID     = newDID
      writeFileSync(`did-${MY_ID.slice(0, 8)}.json`, JSON.stringify(MY_DID, null, 2))
      await broadcastTransaction(res.transaction)
      console.log(`✅ Key rotated on native blockchain! Broadcasted to network. New PubKey: ${publicKey.slice(0, 24)}...`)
    } else {
      console.log(`❌ Key rotation failed: ${res.error}`)
    }
  } else if (input.startsWith('lookup')) {
    const target = input.split(' ')[1]
    if (!target) {
      console.log('Usage: lookup <peerId>')
      return
    }
    const fullPeerId = Array.from(blockchain.state.keys()).find(p => p.startsWith(target)) || target
    const rec = await blockchain.resolveKey(fullPeerId)
    if (!rec) {
      console.log(`❌ No record found on blockchain for ${target}`)
    } else {
      console.log('📄 Native Blockchain Record:')
      console.log(`   Peer ID       : ${rec.peerId}`)
      console.log(`   DID URI       : ${rec.didUri}`)
      console.log(`   Public Key    : ${rec.publicKeyHex.slice(0, 32)}...`)
      console.log(`   Status        : ${rec.isRevoked ? '🛑 REVOKED' : '✅ ACTIVE'}`)
      if (rec.isRevoked) console.log(`   Reason Code   : ${rec.reason}`)
      console.log(`   Registered At : ${new Date(rec.createdAt).toLocaleString()}`)
      console.log(`   Updated At    : ${new Date(rec.updatedAt).toLocaleString()}`)
      const hist = blockchain.getKeyHistory(fullPeerId)
      console.log(`   Key History   : ${hist.length} key version(s)`)
    }
  } else {
    if (activeChannel && activeChannel !== '#general') {
      await sendChannelMessage(activeChannel, input)
    } else {
      await sendBroadcast(input)
    }
  }
})