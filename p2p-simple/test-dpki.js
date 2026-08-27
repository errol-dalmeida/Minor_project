import { BlockchainClient, RevocationReason } from './blockchain.js'
import { generateKeyPair, createDID, signMessage, verifyMessage } from './crypto.js'

async function runDPKITest() {
  console.log('================================================================');
  console.log(' 🧪 RUNNING DECENTRALIZED PKI (BLOCKCHAIN DPKI) TEST SUITE');
  console.log('================================================================\n');

  // Step 1: Initialize Blockchain Client
  console.log('1️⃣  Initializing Blockchain Client...');
  const bcClientA = new BlockchainClient({ walletIndex: 0 });
  const bcClientB = new BlockchainClient({ walletIndex: 1 });

  const connected = await bcClientA.init();
  if (!connected) {
    console.error('❌ Could not connect to local Hardhat node. Run "npx hardhat node" first.');
    process.exit(1);
  }
  await bcClientB.init();
  console.log('   ✅ Connected to IdentityRegistry smart contract.\n');

  // Step 2: Generate Peer A Identity
  console.log('2️⃣  Generating Cryptographic Keys & DIDs for Peer A...');
  const peerA_ID = '12D3KooWPeerA' + Math.random().toString(36).substring(2, 8);
  const peerA_Keys = generateKeyPair();
  const peerA_DID = createDID(peerA_ID, peerA_Keys.publicKey);
  console.log(`   Peer ID  : ${peerA_ID}`);
  console.log(`   DID URI  : ${peerA_DID.id}`);
  console.log(`   Public Key: ${peerA_Keys.publicKey.slice(0, 32)}...\n`);

  // Step 3: Register Peer A on Blockchain
  console.log('3️⃣  Registering Peer A on-chain via IdentityRegistry contract...');
  const regResult = await bcClientA.registerKey(peerA_ID, peerA_Keys.publicKey, peerA_DID.id);
  if (!regResult.success) throw new Error('Registration failed');
  console.log(`   ✅ On-Chain Registration Confirmed! Tx: ${regResult.txHash}\n`);

  // Step 4: Resolve Peer A from Peer B (Decentralized Key Discovery)
  console.log('4️⃣  Resolving Peer A identity from Peer B via Blockchain...');
  const resolved = await bcClientB.resolveKey(peerA_ID);
  console.log(`   Resolved Owner Address: ${resolved.owner}`);
  console.log(`   Resolved Public Key   : ${resolved.publicKeyHex.slice(0, 32)}...`);
  console.log(`   Is Revoked            : ${resolved.isRevoked}`);
  
  if (resolved.publicKeyHex !== peerA_Keys.publicKey) {
    throw new Error('Resolved public key does not match registered key!');
  }
  console.log('   ✅ Key Discovery & Resolution Verified!\n');

  // Step 5: Test P2P Message Signing & Verification
  console.log('5️⃣  Testing P2P Message Signing & Verification against on-chain key...');
  const sampleMessage = 'Hello from Peer A, signed cryptographically!';
  const validSignature = signMessage(sampleMessage, peerA_Keys.privateKey);
  
  const checkValid = await bcClientB.verifyKey(peerA_ID, resolved.publicKeyHex);
  const sigVerified = verifyMessage(sampleMessage, validSignature, resolved.publicKeyHex);

  console.log(`   On-Chain Key Status : ${checkValid.status}`);
  console.log(`   Signature Valid     : ${sigVerified}`);
  if (!checkValid.isValid || !sigVerified) throw new Error('Valid signature verification failed');
  console.log('   ✅ Normal Communication & Verification Passed!\n');

  // Step 6: Test Forged Signature Detection
  console.log('6️⃣  Testing Adversarial Forged Signature Detection...');
  const forgedSig = 'deadbeef00112233445566778899aabbccddeeff';
  const forgedResult = verifyMessage(sampleMessage, forgedSig, resolved.publicKeyHex);
  console.log(`   Forged Signature Verification Result: ${forgedResult} (Expected: false)`);
  if (forgedResult !== false) throw new Error('Forged signature unexpectedly passed!');
  console.log('   ✅ Forged Signature Correctly Rejected!\n');

  // Step 7: Test Cryptographic Key Revocation
  console.log('7️⃣  Revoking Peer A Key on-chain (Simulating Key Compromise)...');
  const revokeResult = await bcClientA.revokeKey(peerA_ID, RevocationReason.KEY_COMPROMISE);
  if (!revokeResult.success) throw new Error('Revocation failed');
  console.log(`   ✅ On-Chain Revocation Confirmed! Tx: ${revokeResult.txHash}`);

  // Query state after revocation
  const postRevokeStatus = await bcClientB.verifyKey(peerA_ID, resolved.publicKeyHex);
  console.log(`   Is Key Revoked on-chain : ${postRevokeStatus.isRevoked}`);
  console.log(`   Key Status              : ${postRevokeStatus.status}`);
  if (!postRevokeStatus.isRevoked) throw new Error('Key was not reported as revoked on-chain!');
  console.log('   ✅ Zero-Trust Revocation Enforcement Verified! Messages from this key will be discarded.\n');

  // Step 7b: Test Unrevocation (Reinstatement)
  console.log('7️⃣b Testing Key Unrevocation (Reinstatement)...');
  const unrevResult = await bcClientA.unrevokeKey(peerA_ID);
  if (!unrevResult.success) throw new Error('Unrevocation failed');
  const postUnrevStatus = await bcClientB.verifyKey(peerA_ID, resolved.publicKeyHex);
  console.log(`   Is Key Revoked after unrevoke : ${postUnrevStatus.isRevoked}`);
  console.log(`   Key Status                    : ${postUnrevStatus.status}`);
  if (postUnrevStatus.isRevoked) throw new Error('Key is still revoked after unrevoke!');
  console.log('   ✅ Reinstatement / Unrevocation Verified! Key is active again.\n');

  // Step 8: Test Key Rotation
  console.log('8️⃣  Testing Key Rotation for a new node (Peer C)...');
  const peerC_ID = '12D3KooWPeerC' + Math.random().toString(36).substring(2, 8);
  const peerC_Keys1 = generateKeyPair();
  const peerC_DID1 = createDID(peerC_ID, peerC_Keys1.publicKey);
  await bcClientA.registerKey(peerC_ID, peerC_Keys1.publicKey, peerC_DID1.id);

  const peerC_Keys2 = generateKeyPair();
  const peerC_DID2 = createDID(peerC_ID, peerC_Keys2.publicKey);
  const rotResult = await bcClientA.rotateKey(peerC_ID, peerC_Keys2.publicKey, peerC_DID2.id);
  if (!rotResult.success) throw new Error('Key rotation failed');

  const resolvedC = await bcClientB.resolveKey(peerC_ID);
  console.log(`   New Active Key: ${resolvedC.publicKeyHex.slice(0, 32)}...`);
  if (resolvedC.publicKeyHex !== peerC_Keys2.publicKey) throw new Error('Key rotation did not update active key');
  console.log('   ✅ Key Rotation & Continuity Verified!\n');

  console.log('================================================================');
  console.log(' 🎉 ALL BLOCKCHAIN DPKI INTEGRATION TESTS PASSED (100%)');
  console.log('================================================================');
}

runDPKITest().catch((err) => {
  console.error('\n❌ Test Suite Failed:', err);
  process.exit(1);
});
