import { createLibp2p } from 'libp2p'
import { tcp } from '@libp2p/tcp'
import { mplex } from '@libp2p/mplex'
import { noise } from '@chainsafe/libp2p-noise'
import { bootstrap } from '@libp2p/bootstrap'
import { mdns } from '@libp2p/mdns'
import { fromString, toString } from 'uint8arrays'
import { generateKeyPair, createDID, signMessage, verifyMessage } from './crypto.js'
import * as readline from 'readline'
import { writeFileSync } from 'fs'

// ── PASTE RELAY ADDRESS HERE ──────────────────────────────────────
const BOOTSTRAP_ADDR = '/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWDrVXBueH62aGpGxdeYU8AJFUT6n38xfmNMRXydtk682S'
// ─────────────────────────────────────────────────────────────────

const RELAY_ID = BOOTSTRAP_ADDR.split('/p2p/')[1]

// Step 2: Generate ECDSA keypair + DID for this peer
const { privateKey, publicKey } = generateKeyPair()

// Step 4: Trust score database
const trustScores = new Map()  // peerId → score
const keyRegistry  = new Map() // peerId → publicKeyHex
const peers        = new Set() // active peer IDs
const lastSeen     = new Map() // peerId → timestamp

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
const MY_DID = createDID(MY_ID, publicKey)

writeFileSync(
  `did-${MY_ID.slice(0, 8)}.json`,
  JSON.stringify(MY_DID, null, 2)
)
console.log(`📄 DID saved to: did-${MY_ID.slice(0, 8)}.json`)

// ── Protocol 1: DID announcement ────────────────────────────────
// Step 3: When connected, share our DID + public key
node.handle('/did/1.0.0', async ({ stream, connection }) => {
  const sender = connection.remotePeer.toString()
  for await (const chunk of stream.source) {
    try {
      const { peerId, did, publicKey: theirKey } = JSON.parse(toString(chunk.subarray()))
      keyRegistry.set(peerId, theirKey)
      if (!trustScores.has(peerId)) {
        trustScores.set(peerId, 50)
        console.log(`\n🆔 DID received from: ${peerId.slice(0,16)}...`)
        console.log(`   DID  : ${did.id}`)
        console.log(`   Trust initialized: 50/100`)
      }
    } catch {}
  }
})

// ── Protocol 2: Signed chat messages ────────────────────────────
// Step 6: Verify signature on received messages
node.handle('/chat/1.0.0', async ({ stream, connection }) => {
  const sender = connection.remotePeer.toString()
  for await (const chunk of stream.source) {
    try {
      const { message, signature } = JSON.parse(toString(chunk.subarray()))

      const senderKey = keyRegistry.get(sender)
      if (!senderKey) {
        console.log(`\n⚠️  Message from ${sender.slice(0,16)}... — no DID yet`)
        continue
      }

      // Step 6: Verify ECDSA signature using public key from gossip
      const valid   = verifyMessage(message, signature, senderKey)
      const current = trustScores.get(sender) ?? 50
      lastSeen.set(sender, Date.now())

      if (valid) {
        const next = Math.min(100, current + 5)
        trustScores.set(sender, next)
        console.log(`\n📩 [✅ VERIFIED] ${sender.slice(0,16)}...: ${message}`)
        console.log(`   Trust: ${current} → ${next}`)
      } else {
        const next = Math.max(0, current - 20)
        trustScores.set(sender, next)
        console.log(`\n📩 [❌ INVALID ] ${sender.slice(0,16)}...: bad signature!`)
        console.log(`   Trust: ${current} → ${next}`)
      }
    } catch {}
  }
})

await node.start()

console.log('\n✅ Peer started')
console.log('Peer ID :', MY_ID)
console.log('DID     :', MY_DID.id)
console.log('PubKey  :', publicKey.slice(0, 20) + '...')
console.log('\nCommands: type a message | "trust" | "peers" | Ctrl+C to quit\n')

// Step 3: Announce our DID to a newly connected peer
async function announceDID(peerId) {
  try {
    const stream  = await node.dialProtocol(peerId, '/did/1.0.0')
    const payload = JSON.stringify({ peerId: MY_ID, did: MY_DID, publicKey })
    await stream.sink([fromString(payload)])
  } catch {}
}

node.addEventListener('peer:connect', async (e) => {
  const id = e.detail.toString()
  if (id === RELAY_ID) { console.log('🔗 Connected to relay'); return }
  peers.add(id)
  lastSeen.set(id, Date.now())
  console.log(`\n🔗 Peer joined: ${id.slice(0,16)}... (${peers.size} peer(s))`)
  // Step 3: share DID immediately on connect
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

// Step 5: Sign and send message to all peers
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
    seen.add(id)
    try {
      const stream = await node.dialProtocol(conn.remotePeer, '/chat/1.0.0')
      await stream.sink([fromString(payload)])
      sent++
    } catch {}
  }
  console.log(`📤 Sent to ${sent} peer(s)`)
}

function printTrustScores() {
  console.log('\n📊 Trust Scores:')
  if (trustScores.size === 0) { console.log('   (none yet)'); return }
  trustScores.forEach((score, peerId) => {
    const bar   = '█'.repeat(Math.floor(score / 10))
    const empty = '░'.repeat(10 - Math.floor(score / 10))
    console.log(`   ${peerId.slice(0,16)}... [${bar}${empty}] ${score}/100`)
  })
  console.log()
}

function printPeers() {
  console.log(`\n👥 Connected peers: ${peers.size}`)
  peers.forEach(id => console.log(`   ${id.slice(0,16)}...`))
  console.log()
}

// Uptime bonus: reward peers that are actively sending messages
function applyUptimeBonus() {
  const now = Date.now()
  trustScores.forEach((score, peerId) => {
    const seen = lastSeen.get(peerId)
    if (seen && now - seen < 60_000) {
      const next = Math.min(100, score + 1)
      trustScores.set(peerId, next)
      console.log(`⏱️  Uptime bonus → ${peerId.slice(0,16)}... trust: ${score} → ${next}`)
    }
  })
}

setInterval(applyUptimeBonus, 30_000)

const rl = readline.createInterface({ input: process.stdin })
rl.on('line', async (line) => {
  const input = line.trim()
  if (!input) return
  if (input === 'trust') printTrustScores()
  else if (input === 'peers') printPeers()
  else await sendToAll(input)
})