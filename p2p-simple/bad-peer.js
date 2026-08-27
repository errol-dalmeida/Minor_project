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

const BOOTSTRAP_ADDR = process.env.RELAY_ADDR || '/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWDrVXBueH62aGpGxdeYU8AJFUT6n38xfmNMRXydtk682S'
const RELAY_ID = BOOTSTRAP_ADDR.includes('/p2p/') ? BOOTSTRAP_ADDR.split('/p2p/')[1] : ''

const { privateKey, publicKey } = generateKeyPair()
const trustScores = new Map()
const keyRegistry = new Map()
const peers       = new Set()

const walletIndexArg = process.argv[2] ? parseInt(process.argv[2]) : (process.env.WALLET_INDEX ? parseInt(process.env.WALLET_INDEX) : 2)
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
const MY_DID = createDID(MY_ID, publicKey)

const bcConnected = await blockchain.init()
if (bcConnected) {
  console.log(`⛓️  [BadPeer] Blockchain connected for adversarial testing.`)
}

// Attack modes:
// 1. 'forge'    - Send fake/corrupted signatures
// 2. 'revoked'  - Register, revoke own key, then try sending messages
// 3. 'valid'    - Normal compliant behavior
let attackMode = 'forge'

node.handle('/did/1.0.0', async ({ stream, connection }) => {
  const sender = connection.remotePeer.toString()
  for await (const chunk of stream.source) {
    try {
      const { peerId, publicKey: theirKey } = JSON.parse(toString(chunk.subarray()))
      keyRegistry.set(peerId, theirKey)
    } catch {}
  }
})

node.handle('/chat/1.0.0', async ({ stream, connection }) => {
  for await (const chunk of stream.source) {
    try {
      const { message } = JSON.parse(toString(chunk.subarray()))
      console.log(`\n📩 Received: ${message}`)
    } catch {}
  }
})

await node.start()

console.log('\n⚠️  [Adversary Node Started]')
console.log('Peer ID    :', MY_ID)
console.log('Attack Mode:', attackMode.toUpperCase())
console.log('\nCommands:')
console.log('  <message>       - Send message using current attack mode')
console.log('  mode forge      - Set attack mode to send corrupted signatures')
console.log('  mode revoked    - Register on-chain, revoke key, and send messages with revoked key')
console.log('  mode valid      - Send valid signatures')
console.log('  peers           - Show connected peers\n')

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
  console.log(`\n🔗 Peer joined: ${id.slice(0,16)}...`)
  setTimeout(() => announceDID(e.detail), 500)
})

node.addEventListener('peer:disconnect', (e) => {
  const id = e.detail.toString()
  if (id === RELAY_ID) return
  peers.delete(id)
})

node.addEventListener('peer:discovery', async (evt) => {
  const peerId = evt.detail.id
  const id = peerId.toString()
  if (id === MY_ID || id === RELAY_ID) return
  try { await node.dial(peerId) } catch {}
})

async function sendToAll(message) {
  const connections = node.getConnections()
  const peerConns   = connections.filter(c => c.remotePeer.toString() !== RELAY_ID)

  if (peerConns.length === 0) {
    console.log('⚠️  No peers connected yet')
    return
  }

  let signature = ''
  if (attackMode === 'forge') {
    signature = 'deadbeef_invalid_signature_hex_12345'
    console.log('😈 Attacking: Sending message with forged signature...')
  } else {
    signature = signMessage(message, privateKey)
    if (attackMode === 'revoked') {
      console.log('😈 Attacking: Sending message with cryptographically REVOKED key...')
    } else {
      console.log('😇 Sending compliant signed message...')
    }
  }

  const payload = JSON.stringify({ message, signature })
  const seen    = new Set()
  let sent      = 0

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
  console.log(`📤 Dispatched attack payload to ${sent} peer(s)`)
}

const rl = readline.createInterface({ input: process.stdin })
rl.on('line', async (line) => {
  const input = line.trim()
  if (!input) return

  if (input.startsWith('mode')) {
    const mode = input.split(' ')[1]
    if (['forge', 'revoked', 'valid'].includes(mode)) {
      attackMode = mode
      if (attackMode === 'revoked' && blockchain.isOnline) {
        console.log('⛓️  Registering then immediately revoking on-chain key...')
        await blockchain.registerKey(MY_ID, publicKey, MY_DID.id)
        await blockchain.revokeKey(MY_ID, RevocationReason.KEY_COMPROMISE)
        console.log('🛑 Key revoked on-chain! Ready to test revoked-key attacks.')
      }
      console.log(`✅ Attack mode switched to: ${attackMode.toUpperCase()}`)
    } else {
      console.log('Unknown mode. Options: forge, revoked, valid')
    }
  } else if (input === 'peers') {
    console.log(`Connected peers: ${peers.size}`)
  } else {
    await sendToAll(input)
  }
})