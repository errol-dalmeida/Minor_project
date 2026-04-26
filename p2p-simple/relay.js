import { createLibp2p } from 'libp2p'
import { tcp } from '@libp2p/tcp'
import { mplex } from '@libp2p/mplex'
import { noise } from '@chainsafe/libp2p-noise'

const node = await createLibp2p({
  addresses: { listen: ['/ip4/0.0.0.0/tcp/4001'] },
  transports: [tcp()],
  streamMuxers: [mplex()],
  connectionEncryption: [noise()]
})

await node.start()
console.log('✅ Relay running')
console.log('Peer ID:', node.peerId.toString())
node.getMultiaddrs().forEach(a => console.log(a.toString()))

node.addEventListener('peer:connect',    e => console.log('🔗 Peer connected:', e.detail.toString()))
node.addEventListener('peer:disconnect', e => console.log('🔌 Peer left:     ', e.detail.toString()))