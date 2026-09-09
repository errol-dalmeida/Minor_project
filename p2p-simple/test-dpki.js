import { NativeBlockchain, RevocationReason } from './blockchain.js'
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

async function runNativeDPKITest() {
  console.log('================================================================');
  console.log(' 🧪 RUNNING NATIVE P2P BLOCKCHAIN, ECC E2EE & CHANNELS TEST SUITE');
  console.log('================================================================\n');

  // ─────────────────────────────────────────────────────────────
  // 1. Native Blockchain Initialization
  // ─────────────────────────────────────────────────────────────
  console.log('1️⃣  Initializing Native In-Code P2P Blockchains (Node A & Node B)...');
  const chainNodeA = new NativeBlockchain({ difficulty: 1 });
  const chainNodeB = new NativeBlockchain({ difficulty: 1 });

  console.log(`   Node A Genesis Block Hash: ${chainNodeA.getLatestBlock().hash.slice(0, 24)}...`);
  console.log(`   Node B Genesis Block Hash: ${chainNodeB.getLatestBlock().hash.slice(0, 24)}...`);
  if (chainNodeA.getLatestBlock().hash !== chainNodeB.getLatestBlock().hash) {
    throw new Error('Genesis block mismatch between nodes!');
  }
  console.log('   ✅ Deterministic Genesis Blocks Initialized.\n');

  // ─────────────────────────────────────────────────────────────
  // 2. Peer Identity Creation & On-Chain Registration
  // ─────────────────────────────────────────────────────────────
  console.log('2️⃣  Generating ECC Keypair (NIST P-256) & W3C DID for Peer A...');
  const peerA_ID = '12D3KooWPeerA_' + Math.random().toString(36).substring(2, 8);
  const peerA_Keys = generateKeyPair();
  const peerA_DID = createDID(peerA_ID, peerA_Keys.publicKey);

  console.log(`   Peer ID     : ${peerA_ID}`);
  console.log(`   DID URI     : ${peerA_DID.id}`);
  console.log(`   Public Key  : ${peerA_Keys.publicKey.slice(0, 32)}...`);

  console.log('   Submitting REGISTER_KEY transaction on Node A...');
  const regResult = await chainNodeA.registerKey(peerA_ID, peerA_Keys.publicKey, peerA_DID.id, peerA_Keys.privateKey);
  if (!regResult.success) throw new Error(`Registration failed: ${regResult.error}`);
  console.log(`   ✅ Registered in Block #${regResult.block.index}! Block Hash: ${regResult.block.hash.slice(0, 24)}...\n`);

  // ─────────────────────────────────────────────────────────────
  // 3. P2P Chain Synchronization & Longest-Chain Rule
  // ─────────────────────────────────────────────────────────────
  console.log('3️⃣  Testing P2P Block Synchronization from Node A to Node B...');
  const syncSuccess = chainNodeB.replaceChain(chainNodeA.chain);
  if (!syncSuccess) throw new Error('Node B failed to synchronize chain from Node A');
  console.log(`   Node B Chain Height: ${chainNodeB.chain.length} block(s)`);

  const resolvedA = await chainNodeB.resolveKey(peerA_ID);
  if (!resolvedA || resolvedA.publicKeyHex !== peerA_Keys.publicKey) {
    throw new Error('Resolved public key on Node B does not match registered key!');
  }
  console.log(`   Resolved Public Key on Node B: ${resolvedA.publicKeyHex.slice(0, 32)}...`);
  console.log('   ✅ P2P Blockchain Synchronization Verified!\n');

  // ─────────────────────────────────────────────────────────────
  // 4. Confidential 1-on-1 End-to-End Encryption (ECIES via ECC)
  // ─────────────────────────────────────────────────────────────
  console.log('4️⃣  Testing Confidential 1-on-1 Direct Messaging (ECIES / ECC + AES-256-GCM)...');
  const peerB_ID = '12D3KooWPeerB_' + Math.random().toString(36).substring(2, 8);
  const peerB_Keys = generateKeyPair();
  const peerB_DID = createDID(peerB_ID, peerB_Keys.publicKey);
  await chainNodeA.registerKey(peerB_ID, peerB_Keys.publicKey, peerB_DID.id, peerB_Keys.privateKey);
  chainNodeB.replaceChain(chainNodeA.chain);

  const secretMessage = 'Top secret confidential message: Coordinates 45.123, -93.456';
  console.log(`   Plaintext Message: "${secretMessage}"`);

  // Alice encrypts for Bob using Bob's public key (from blockchain) and Alice's private key
  const encryptedPayload = encryptECC(secretMessage, peerB_Keys.publicKey, peerA_Keys.privateKey);
  console.log(`   Ciphertext (Hex) : ${encryptedPayload.ciphertext.slice(0, 36)}...`);
  console.log(`   IV (Hex)         : ${encryptedPayload.iv}`);
  console.log(`   Auth Tag (Hex)   : ${encryptedPayload.tag}`);

  // Bob decrypts using Alice's public key (from blockchain) and Bob's private key
  const decryptedMessage = decryptECC(encryptedPayload, peerA_Keys.publicKey, peerB_Keys.privateKey);
  console.log(`   Decrypted Message: "${decryptedMessage}"`);
  if (decryptedMessage !== secretMessage) throw new Error('ECIES Decryption failed to recover plaintext!');
  console.log('   ✅ End-to-End Asymmetric Encryption (ECIES) Passed 100%!\n');

  // ─────────────────────────────────────────────────────────────
  // 5. Authentication & Digital Signatures (ECDSA SHA-256)
  // ─────────────────────────────────────────────────────────────
  console.log('5️⃣  Testing ECDSA Digital Signatures over Encrypted Payloads...');
  const sigPayload = `${encryptedPayload.ciphertext}:${encryptedPayload.iv}:${encryptedPayload.tag}:1740000000`;
  const signature = signMessage(sigPayload, peerA_Keys.privateKey);
  const validSig = verifyMessage(sigPayload, signature, peerA_Keys.publicKey);
  console.log(`   Signature (DER Hex): ${signature.slice(0, 36)}...`);
  console.log(`   Signature Valid    : ${validSig}`);
  if (!validSig) throw new Error('ECDSA Signature verification failed');

  // Test forged signature detection
  const forgedSig = '30440220111122223333444455556666777788889999aaaabbbbccccddddeeeeffff000002209999888877776666555544443333222211110000aaaabbbbccccddddeeeeffff1111';
  const forgedCheck = verifyMessage(sigPayload, forgedSig, peerA_Keys.publicKey);
  console.log(`   Adversarial Forged Signature Rejected: ${!forgedCheck}`);
  if (forgedCheck) throw new Error('Forged signature unexpectedly passed verification!');
  console.log('   ✅ Digital Signature Authentication & Forgery Detection Verified!\n');

  // ─────────────────────────────────────────────────────────────
  // 6. Custom Group Channel Encryption
  // ─────────────────────────────────────────────────────────────
  console.log('6️⃣  Testing Custom Group Channel Encryption (#dev Channel)...');
  const channelName = '#dev';
  const channelKey = sha256(`channel-key-salt-${channelName}`);
  const groupMsg = 'Dev Team: Pull request #42 is ready for code review.';

  const encGroup = encryptChannelMessage(groupMsg, channelKey);
  const decGroup = decryptChannelMessage(encGroup, channelKey);
  console.log(`   Channel Message  : "${groupMsg}"`);
  console.log(`   Channel Encrypted: ${encGroup.ciphertext.slice(0, 36)}...`);
  console.log(`   Channel Decrypted: "${decGroup}"`);
  if (decGroup !== groupMsg) throw new Error('Group channel message decryption failed');
  console.log('   ✅ Custom Group Channel Encryption Passed!\n');

  // ─────────────────────────────────────────────────────────────
  // 7. Cryptographic Key Revocation (DPKI)
  // ─────────────────────────────────────────────────────────────
  console.log('7️⃣  Testing Key Revocation (Simulating Key Compromise)...');
  const revokeResult = await chainNodeA.revokeKey(peerA_ID, RevocationReason.KEY_COMPROMISE, peerA_Keys.privateKey);
  if (!revokeResult.success) throw new Error('Key revocation failed');
  chainNodeB.replaceChain(chainNodeA.chain);

  const postRevokeStatus = await chainNodeB.verifyKey(peerA_ID, peerA_Keys.publicKey);
  console.log(`   Is Key Revoked on-chain : ${postRevokeStatus.isRevoked}`);
  console.log(`   Key Status              : ${postRevokeStatus.status}`);
  if (!postRevokeStatus.isRevoked) throw new Error('Key was not reported as revoked on blockchain!');
  console.log('   ✅ Key Revocation Verified! Subsequent messages from revoked key will be quarantined.\n');

  // ─────────────────────────────────────────────────────────────
  // 8. Key Unrevocation (Reinstatement)
  // ─────────────────────────────────────────────────────────────
  console.log('8️⃣  Testing Key Unrevocation / Reinstatement...');
  const unrevResult = await chainNodeA.unrevokeKey(peerA_ID, peerA_Keys.privateKey);
  if (!unrevResult.success) throw new Error('Key unrevocation failed');
  chainNodeB.replaceChain(chainNodeA.chain);

  const postUnrevStatus = await chainNodeB.verifyKey(peerA_ID, peerA_Keys.publicKey);
  console.log(`   Is Key Revoked after unrevoke : ${postUnrevStatus.isRevoked}`);
  console.log(`   Key Status                    : ${postUnrevStatus.status}`);
  if (postUnrevStatus.isRevoked) throw new Error('Key is still revoked after unrevoking!');
  console.log('   ✅ Key Reinstatement Verified!\n');

  // ─────────────────────────────────────────────────────────────
  // 9. Key Rotation & Continuity
  // ─────────────────────────────────────────────────────────────
  console.log('9️⃣  Testing Key Rotation...');
  const peerA_Keys_v2 = generateKeyPair();
  const peerA_DID_v2 = createDID(peerA_ID, peerA_Keys_v2.publicKey);

  const rotResult = await chainNodeA.rotateKey(peerA_ID, peerA_Keys_v2.publicKey, peerA_DID_v2.id, peerA_Keys.privateKey);
  if (!rotResult.success) throw new Error(`Key rotation failed: ${rotResult.error}`);
  chainNodeB.replaceChain(chainNodeA.chain);

  const resolvedRotated = await chainNodeB.resolveKey(peerA_ID);
  console.log(`   New Active Key : ${resolvedRotated.publicKeyHex.slice(0, 32)}...`);
  if (resolvedRotated.publicKeyHex !== peerA_Keys_v2.publicKey) {
    throw new Error('Key rotation did not update active public key!');
  }
  const history = chainNodeB.getKeyHistory(peerA_ID);
  console.log(`   Key History    : ${history.length} key version(s) in audit trail`);
  if (history.length !== 2) throw new Error('Key history length mismatch!');
  console.log('   ✅ Key Rotation & Cryptographic Audit Trail Verified!\n');

  console.log('================================================================');
  console.log(' 🎉 ALL NATIVE BLOCKCHAIN, ECC E2EE & CHANNELS TESTS PASSED (100%)');
  console.log('================================================================');
}

runNativeDPKITest().catch((err) => {
  console.error('\n❌ Test Suite Failed:', err);
  process.exit(1);
});
