import asyncio
import random
import string
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from blockchain import NativeBlockchain, RevocationReason
from crypto import (
    generate_key_pair,
    create_did,
    sign_message,
    verify_message,
    encrypt_ecc,
    decrypt_ecc,
    generate_channel_key,
    encrypt_channel_message,
    decrypt_channel_message,
    sha256
)


async def run_native_dpki_test():
    print("================================================================")
    print(" 🧪 RUNNING NATIVE P2P BLOCKCHAIN, ECC E2EE & CHANNELS TEST SUITE")
    print("================================================================\n")

    # ─────────────────────────────────────────────────────────────
    # 1. Native Blockchain Initialization
    # ─────────────────────────────────────────────────────────────
    print("1️⃣  Initializing Native In-Code P2P Blockchains (Node A & Node B)...")
    chain_node_a = NativeBlockchain(difficulty=1)
    chain_node_b = NativeBlockchain(difficulty=1)

    print(f"   Node A Genesis Block Hash: {chain_node_a.get_latest_block().hash[:24]}...")
    print(f"   Node B Genesis Block Hash: {chain_node_b.get_latest_block().hash[:24]}...")
    if chain_node_a.get_latest_block().hash != chain_node_b.get_latest_block().hash:
        raise RuntimeError("Genesis block mismatch between nodes!")
    print("   ✅ Deterministic Genesis Blocks Initialized.\n")

    # ─────────────────────────────────────────────────────────────
    # 2. Peer Identity Creation & On-Chain Registration
    # ─────────────────────────────────────────────────────────────
    print("2️⃣  Generating ECC Keypair (NIST P-256) & W3C DID for Peer A...")
    random_suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    peer_a_id = f"12D3KooWPeerA_{random_suffix}"
    peer_a_keys = generate_key_pair()
    peer_a_did = create_did(peer_a_id, peer_a_keys["publicKey"])

    print(f"   Peer ID     : {peer_a_id}")
    print(f"   DID URI     : {peer_a_did['id']}")
    print(f"   Public Key  : {peer_a_keys['publicKey'][:32]}...")

    print("   Submitting REGISTER_KEY transaction on Node A...")
    reg_result = await chain_node_a.register_key(
        peer_a_id,
        peer_a_keys["publicKey"],
        peer_a_did["id"],
        peer_a_keys["privateKey"]
    )
    if not reg_result.get("success"):
        raise RuntimeError(f"Registration failed: {reg_result.get('error')}")
    print(f"   ✅ Registered in Block #{reg_result['block'].index}! Block Hash: {reg_result['block'].hash[:24]}...\n")

    # ─────────────────────────────────────────────────────────────
    # 3. P2P Chain Synchronization & Longest-Chain Rule
    # ─────────────────────────────────────────────────────────────
    print("3️⃣  Testing P2P Block Synchronization from Node A to Node B...")
    sync_success = chain_node_b.replace_chain(chain_node_a.chain)
    if not sync_success:
        raise RuntimeError("Node B failed to synchronize chain from Node A")
    print(f"   Node B Chain Height: {len(chain_node_b.chain)} block(s)")

    resolved_a = await chain_node_b.resolve_key(peer_a_id)
    if not resolved_a or resolved_a.get("publicKeyHex") != peer_a_keys["publicKey"]:
        raise RuntimeError("Resolved public key on Node B does not match registered key!")
    print(f"   Resolved Public Key on Node B: {resolved_a['publicKeyHex'][:32]}...")
    print("   ✅ P2P Blockchain Synchronization Verified!\n")

    # ─────────────────────────────────────────────────────────────
    # 4. Confidential 1-on-1 End-to-End Encryption (ECIES via ECC)
    # ─────────────────────────────────────────────────────────────
    print("4️⃣  Testing Confidential 1-on-1 Direct Messaging (ECIES / ECC + AES-256-GCM)...")
    random_suffix_b = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    peer_b_id = f"12D3KooWPeerB_{random_suffix_b}"
    peer_b_keys = generate_key_pair()
    peer_b_did = create_did(peer_b_id, peer_b_keys["publicKey"])
    await chain_node_a.register_key(peer_b_id, peer_b_keys["publicKey"], peer_b_did["id"], peer_b_keys["privateKey"])
    chain_node_b.replace_chain(chain_node_a.chain)

    secret_message = "Top secret confidential message: Coordinates 45.123, -93.456"
    print(f'   Plaintext Message: "{secret_message}"')

    # Alice encrypts for Bob using Bob's public key (from blockchain) and Alice's private key
    encrypted_payload = encrypt_ecc(secret_message, peer_b_keys["publicKey"], peer_a_keys["privateKey"])
    print(f"   Ciphertext (Hex) : {encrypted_payload['ciphertext'][:36]}...")
    print(f"   IV (Hex)         : {encrypted_payload['iv']}")
    print(f"   Auth Tag (Hex)   : {encrypted_payload['tag']}")

    # Bob decrypts using Alice's public key (from blockchain) and Bob's private key
    decrypted_message = decrypt_ecc(encrypted_payload, peer_a_keys["publicKey"], peer_b_keys["privateKey"])
    print(f'   Decrypted Message: "{decrypted_message}"')
    if decrypted_message != secret_message:
        raise RuntimeError("ECIES Decryption failed to recover plaintext!")
    print("   ✅ End-to-End Asymmetric Encryption (ECIES) Passed 100%!\n")

    # ─────────────────────────────────────────────────────────────
    # 5. Authentication & Digital Signatures (ECDSA SHA-256)
    # ─────────────────────────────────────────────────────────────
    print("5️⃣  Testing ECDSA Digital Signatures over Encrypted Payloads...")
    sig_payload = f"{encrypted_payload['ciphertext']}:{encrypted_payload['iv']}:{encrypted_payload['tag']}:1740000000"
    signature = sign_message(sig_payload, peer_a_keys["privateKey"])
    valid_sig = verify_message(sig_payload, signature, peer_a_keys["publicKey"])
    print(f"   Signature (DER Hex): {signature[:36]}...")
    print(f"   Signature Valid    : {valid_sig}")
    if not valid_sig:
        raise RuntimeError("ECDSA Signature verification failed")

    # Test forged signature detection
    forged_sig = "30440220111122223333444455556666777788889999aaaabbbbccccddddeeeeffff000002209999888877776666555544443333222211110000aaaabbbbccccddddeeeeffff1111"
    forged_check = verify_message(sig_payload, forged_sig, peer_a_keys["publicKey"])
    print(f"   Adversarial Forged Signature Rejected: {not forged_check}")
    if forged_check:
        raise RuntimeError("Forged signature unexpectedly passed verification!")
    print("   ✅ Digital Signature Authentication & Forgery Detection Verified!\n")

    # ─────────────────────────────────────────────────────────────
    # 6. Custom Group Channel Encryption
    # ─────────────────────────────────────────────────────────────
    print("6️⃣  Testing Custom Group Channel Encryption (#dev Channel)...")
    channel_name = "#dev"
    channel_key = sha256(f"channel-key-salt-{channel_name}")
    group_msg = "Dev Team: Pull request #42 is ready for code review."

    enc_group = encrypt_channel_message(group_msg, channel_key)
    dec_group = decrypt_channel_message(enc_group, channel_key)
    print(f'   Channel Message  : "{group_msg}"')
    print(f"   Channel Encrypted: {enc_group['ciphertext'][:36]}...")
    print(f'   Channel Decrypted: "{dec_group}"')
    if dec_group != group_msg:
        raise RuntimeError("Group channel message decryption failed")
    print("   ✅ Custom Group Channel Encryption Passed!\n")

    # ─────────────────────────────────────────────────────────────
    # 7. Cryptographic Key Revocation (DPKI)
    # ─────────────────────────────────────────────────────────────
    print("7️⃣  Testing Key Revocation (Simulating Key Compromise)...")
    revoke_result = await chain_node_a.revoke_key(peer_a_id, RevocationReason.KEY_COMPROMISE, peer_a_keys["privateKey"])
    if not revoke_result.get("success"):
        raise RuntimeError("Key revocation failed")
    chain_node_b.replace_chain(chain_node_a.chain)

    post_revoke_status = await chain_node_b.verify_key(peer_a_id, peer_a_keys["publicKey"])
    print(f"   Is Key Revoked on-chain : {post_revoke_status['isRevoked']}")
    print(f"   Key Status              : {post_revoke_status['status']}")
    if not post_revoke_status["isRevoked"]:
        raise RuntimeError("Key was not reported as revoked on blockchain!")
    print("   ✅ Key Revocation Verified! Subsequent messages from revoked key will be quarantined.\n")

    # ─────────────────────────────────────────────────────────────
    # 8. Key Unrevocation (Reinstatement)
    # ─────────────────────────────────────────────────────────────
    print("8️⃣  Testing Key Unrevocation / Reinstatement...")
    unrev_result = await chain_node_a.unrevoke_key(peer_a_id, peer_a_keys["privateKey"])
    if not unrev_result.get("success"):
        raise RuntimeError("Key unrevocation failed")
    chain_node_b.replace_chain(chain_node_a.chain)

    post_unrev_status = await chain_node_b.verify_key(peer_a_id, peer_a_keys["publicKey"])
    print(f"   Is Key Revoked after unrevoke : {post_unrev_status['isRevoked']}")
    print(f"   Key Status                    : {post_unrev_status['status']}")
    if post_unrev_status["isRevoked"]:
        raise RuntimeError("Key is still revoked after unrevoking!")
    print("   ✅ Key Reinstatement Verified!\n")

    # ─────────────────────────────────────────────────────────────
    # 9. Key Rotation & Continuity
    # ─────────────────────────────────────────────────────────────
    print("9️⃣  Testing Key Rotation...")
    peer_a_keys_v2 = generate_key_pair()
    peer_a_did_v2 = create_did(peer_a_id, peer_a_keys_v2["publicKey"])

    rot_result = await chain_node_a.rotate_key(
        peer_a_id,
        peer_a_keys_v2["publicKey"],
        peer_a_did_v2["id"],
        peer_a_keys["privateKey"]
    )
    if not rot_result.get("success"):
        raise RuntimeError(f"Key rotation failed: {rot_result.get('error')}")
    chain_node_b.replace_chain(chain_node_a.chain)

    resolved_rotated = await chain_node_b.resolve_key(peer_a_id)
    print(f"   New Active Key : {resolved_rotated['publicKeyHex'][:32]}...")
    if resolved_rotated.get("publicKeyHex") != peer_a_keys_v2["publicKey"]:
        raise RuntimeError("Key rotation did not update active public key!")
    history = chain_node_b.get_key_history(peer_a_id)
    print(f"   Key History    : {len(history)} key version(s) in audit trail")
    if len(history) != 2:
        raise RuntimeError("Key history length mismatch!")
    print("   ✅ Key Rotation & Cryptographic Audit Trail Verified!\n")

    print("================================================================")
    print(" 🎉 ALL NATIVE BLOCKCHAIN, ECC E2EE & CHANNELS TESTS PASSED (100%)")
    print("================================================================")


if __name__ == "__main__":
    try:
        asyncio.run(run_native_dpki_test())
    except Exception as err:
        print(f"\n❌ Test Suite Failed: {err}", file=sys.stderr)
        sys.exit(1)
