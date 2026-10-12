import asyncio
import sys
import time

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from crypto_modular import (
    CryptoSuite,
    SHA256Provider,
    BLAKE2bProvider,
    SHA3_256Provider,
    NISTP256Provider,
    AESGCMProvider,
    ChaCha20Poly1305Provider
)
from blockchain import RevocationReason
from peer_node import PeerNode
import relay


async def run_modular_tests():
    print("================================================================")
    print(" 🧪 RUNNING MODULAR PLUGGABLE CRYPTO & PEERNODE TEST SUITE")
    print("================================================================\n")

    # ─────────────────────────────────────────────────────────────
    # Phase 1: Test Pluggable Hash Providers
    # ─────────────────────────────────────────────────────────────
    print("1️⃣  Testing Pluggable Hash Strategies...")
    sample_data = "Decentralized PKI & Cryptographic Agility"
    sha256_hash = SHA256Provider().hash(sample_data)
    blake2b_hash = BLAKE2bProvider().hash(sample_data)
    sha3_hash = SHA3_256Provider().hash(sample_data)

    print(f"   SHA-256   : {sha256_hash[:32]}...")
    print(f"   BLAKE2b   : {blake2b_hash[:32]}...")
    print(f"   SHA3-256  : {sha3_hash[:32]}...")
    assert len(sha256_hash) == 64
    assert len(blake2b_hash) == 64
    assert len(sha3_hash) == 64
    assert sha256_hash != blake2b_hash != sha3_hash
    print("   ✅ Pluggable Hash Strategies Verified!\n")

    # ─────────────────────────────────────────────────────────────
    # Phase 2: Test Pluggable Symmetric Ciphers (AES-GCM & ChaCha20)
    # ─────────────────────────────────────────────────────────────
    print("2️⃣  Testing Pluggable Symmetric Ciphers (AES-256-GCM vs ChaCha20-Poly1305)...")
    key = b"\x01" * 32
    secret_text = "Highly confidential mission coordinates: 51.5074, -0.1278"

    # AES-GCM
    aes_provider = AESGCMProvider()
    enc_aes = aes_provider.encrypt(secret_text, key)
    dec_aes = aes_provider.decrypt(enc_aes, key)
    assert dec_aes == secret_text
    print(f"   AES-256-GCM Decrypted: \"{dec_aes[:35]}...\" (Tag: {enc_aes['tag'][:12]}...)")

    # ChaCha20-Poly1305
    chacha_provider = ChaCha20Poly1305Provider()
    enc_chacha = chacha_provider.encrypt(secret_text, key)
    dec_chacha = chacha_provider.decrypt(enc_chacha, key)
    assert dec_chacha == secret_text
    print(f"   ChaCha20-P1305 Decrypted: \"{dec_chacha[:35]}...\" (Tag: {enc_chacha['tag'][:12]}...)")
    print("   ✅ Pluggable Symmetric AEAD Ciphers Verified!\n")

    # ─────────────────────────────────────────────────────────────
    # Phase 3: Test CryptoSuite Aggregation & Algorithm Swapping
    # ─────────────────────────────────────────────────────────────
    print("3️⃣  Testing CryptoSuite Strategy Manager & Hot-Swapping...")
    suite_default = CryptoSuite.default()
    suite_fast = CryptoSuite.modern_fast()

    print(f"   Suite 1: {suite_default.get_descriptor()}")
    print(f"   Suite 2: {suite_fast.get_descriptor()}")

    kp_a = suite_default.generate_keypair()
    kp_b = suite_fast.generate_keypair()

    msg = "Cross-suite cryptographic exchange"
    enc_suite1 = suite_default.encrypt_dm(msg, kp_b["publicKey"], kp_a["privateKey"])
    dec_suite1 = suite_default.decrypt_dm(enc_suite1, kp_a["publicKey"], kp_b["privateKey"])
    assert dec_suite1 == msg
    print(f"   ✅ Suite 1 ECIES Encrypt/Decrypt Successful: \"{dec_suite1}\"\n")

    # ─────────────────────────────────────────────────────────────
    # Phase 4: PeerNode Function-Driven Network Integration
    # ─────────────────────────────────────────────────────────────
    print("4️⃣  Testing Sovereign PeerNode Engine (Pure Python Code Execution)...")
    relay_port = 4015
    server = await asyncio.start_server(relay.handle_client, "127.0.0.1", relay_port)
    print(f"   Relay started on 127.0.0.1:{relay_port}")

    node_alice = PeerNode(peer_id="12D3KooWAliceModular001", relay_port=relay_port, crypto_suite=suite_default)
    node_bob = PeerNode(peer_id="12D3KooWBobModular002", relay_port=relay_port, crypto_suite=suite_default)

    await node_alice.start()
    await node_bob.start()
    await asyncio.sleep(0.6)

    # Alice sends DM to Bob through code function
    dm_text = "Alice speaking: Function-driven code execution works!"
    res_dm = await node_alice.send_direct_message(node_bob.peer_id, dm_text)
    assert res_dm["success"] is True

    await asyncio.sleep(0.5)
    # Check Bob's inbox
    bob_inbox = [m for m in node_bob.message_history if m["kind"] == "INCOMING_DM"]
    assert len(bob_inbox) >= 1
    assert bob_inbox[0]["text"] == dm_text
    print(f"   ✅ Node B received and verified direct message via code: \"{bob_inbox[0]['text']}\"")

    # Alice joins channel and sends message through code function
    await node_alice.join_channel("#research")
    await node_bob.join_channel("#research")
    await asyncio.sleep(0.3)

    ch_text = "Modular channel communication verified."
    res_ch = await node_alice.send_channel_message("#research", ch_text)
    assert res_ch["success"] is True

    await asyncio.sleep(0.5)
    bob_ch_inbox = [m for m in node_bob.message_history if m["kind"] == "INCOMING_CHANNEL"]
    assert len(bob_ch_inbox) >= 1
    assert bob_ch_inbox[0]["text"] == ch_text
    print(f"   ✅ Node B received channel message on #research: \"{bob_ch_inbox[0]['text']}\"")

    # ─────────────────────────────────────────────────────────────
    # Phase 5: On-Chain Key Revocation Quarantine
    # ─────────────────────────────────────────────────────────────
    print("\n5️⃣  Testing On-Chain Revocation via Code Execution...")
    rev_res = await node_alice.revoke_key(reason=RevocationReason.KEY_COMPROMISE)
    assert rev_res["success"] is True
    await asyncio.sleep(0.4)

    # Alice attempts sending another DM to Bob
    quarantined_dm = "This message must be blocked."
    res_blocked = await node_alice.send_direct_message(node_bob.peer_id, quarantined_dm)
    # Node Alice blocked it locally or Node Bob quarantined it
    assert res_blocked["success"] is False

    print("   ✅ Blocked revoked identity from transmitting further DMs.")

    # Cleanup
    await node_alice.stop()
    await node_bob.stop()
    server.close()
    await server.wait_closed()

    print("\n================================================================")
    print(" 🎉 ALL MODULAR CRYPTOGRAPHY & PEERNODE TESTS PASSED (100%)")
    print("================================================================")


if __name__ == "__main__":
    asyncio.run(run_modular_tests())
