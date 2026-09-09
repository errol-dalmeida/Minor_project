import asyncio
import json
import sys
import time

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from crypto import (
    generate_key_pair,
    create_did,
    sign_message,
    verify_message,
    encrypt_ecc,
    decrypt_ecc,
    encrypt_channel_message,
    decrypt_channel_message,
    sha256
)
from blockchain import NativeBlockchain, Transaction, TransactionType, RevocationReason
import relay


async def run_network_e2e_test():
    print("================================================================")
    print(" 🌐 RUNNING ASYNCIO P2P MULTI-NODE NETWORK INTEGRATION TEST")
    print("================================================================\n")

    # 1. Start Relay Server on port 4009
    relay_port = 4009
    server = await asyncio.start_server(relay.handle_client, "127.0.0.1", relay_port)
    print(f"✅ Relay running on 127.0.0.1:{relay_port}")

    # 2. Setup Node A and Node B
    node_a_id = "12D3KooWAliceNode_001"
    node_b_id = "12D3KooWBobNode_002"

    keys_a = generate_key_pair()
    keys_b = generate_key_pair()

    chain_a = NativeBlockchain(difficulty=1)
    chain_b = NativeBlockchain(difficulty=1)

    # Initial registrations on their local chains
    await chain_a.register_key(node_a_id, keys_a["publicKey"], f"did:peer:{node_a_id}", keys_a["privateKey"])
    await chain_b.register_key(node_b_id, keys_b["publicKey"], f"did:peer:{node_b_id}", keys_b["privateKey"])

    # Connect Node A to Relay
    r_a, w_a = await asyncio.open_connection("127.0.0.1", relay_port)
    w_a.write((json.dumps({"type": "REGISTER_PEER", "peerId": node_a_id}) + "\n").encode())
    await w_a.drain()

    # Connect Node B to Relay
    r_b, w_b = await asyncio.open_connection("127.0.0.1", relay_port)
    w_b.write((json.dumps({"type": "REGISTER_PEER", "peerId": node_b_id}) + "\n").encode())
    await w_b.drain()

    print("   Nodes A & B connected to relay.\n")

    # 3. Exchange DIDs
    # Node A announces DID to Node B
    did_payload_a = {
        "type": "ROUTED_MSG",
        "protocol": "/did/1.0.0",
        "sender": node_a_id,
        "target": node_b_id,
        "data": {
            "peerId": node_a_id,
            "did": create_did(node_a_id, keys_a["publicKey"]),
            "publicKey": keys_a["publicKey"]
        }
    }
    w_a.write((json.dumps(did_payload_a) + "\n").encode())
    await w_a.drain()

    # Node B reads message
    line_b = await r_b.readline()
    msg_b = json.loads(line_b.decode())
    # May receive PEER_LIST or PEER_JOINED first
    while msg_b.get("protocol") != "/did/1.0.0":
        line_b = await r_b.readline()
        msg_b = json.loads(line_b.decode())

    received_did = msg_b["data"]
    assert received_did["peerId"] == node_a_id
    assert received_did["publicKey"] == keys_a["publicKey"]
    print("✅ DID exchange routed successfully from Node A to Node B!\n")

    # Also register Node A on Node B's blockchain so Bob recognizes Alice
    await chain_b.register_key(node_a_id, keys_a["publicKey"], f"did:peer:{node_a_id}", keys_a["privateKey"])

    # 4. Send 1-on-1 Confidential DM (Alice to Bob)
    secret_text = "Secret project rendezvous at 18:00 UTC."
    encrypted = encrypt_ecc(secret_text, keys_b["publicKey"], keys_a["privateKey"])
    timestamp = int(time.time() * 1000)
    sig_payload = f"{encrypted['ciphertext']}:{encrypted['iv']}:{encrypted['tag']}:{timestamp}"
    signature = sign_message(sig_payload, keys_a["privateKey"])

    dm_msg = {
        "type": "ROUTED_MSG",
        "protocol": "/chat/dm/1.0.0",
        "sender": node_a_id,
        "target": node_b_id,
        "data": {
            "from": node_a_id,
            "to": node_b_id,
            "encryptedData": encrypted,
            "signature": signature,
            "timestamp": timestamp
        }
    }
    w_a.write((json.dumps(dm_msg) + "\n").encode())
    await w_a.drain()

    # Node B reads DM
    line_b = await r_b.readline()
    msg_b = json.loads(line_b.decode())
    while msg_b.get("protocol") != "/chat/dm/1.0.0":
        line_b = await r_b.readline()
        msg_b = json.loads(line_b.decode())

    dm_data = msg_b["data"]
    # Bob verifies signature
    check_sig = verify_message(
        f"{dm_data['encryptedData']['ciphertext']}:{dm_data['encryptedData']['iv']}:{dm_data['encryptedData']['tag']}:{dm_data['timestamp']}",
        dm_data["signature"],
        keys_a["publicKey"]
    )
    assert check_sig is True
    # Bob decrypts
    decrypted = decrypt_ecc(dm_data["encryptedData"], keys_a["publicKey"], keys_b["privateKey"])
    assert decrypted == secret_text
    print(f'✅ E2EE Confidential DM received and decrypted: "{decrypted}"\n')

    # 5. Channel Messaging
    channel_name = "#secops"
    channel_key = sha256(f"channel-key-salt-{channel_name}")
    ch_text = "Alert: Firewall rule updated on port 443."
    enc_ch = encrypt_channel_message(ch_text, channel_key)
    sig_ch = sign_message(f"{channel_name}:{enc_ch['ciphertext']}:{enc_ch['iv']}:{enc_ch['tag']}:{timestamp}", keys_a["privateKey"])

    ch_msg = {
        "type": "ROUTED_MSG",
        "protocol": "/chat/channel/1.0.0",
        "sender": node_a_id,
        "target": "*",
        "data": {
            "channel": channel_name,
            "from": node_a_id,
            "encryptedData": enc_ch,
            "signature": sig_ch,
            "timestamp": timestamp
        }
    }
    w_a.write((json.dumps(ch_msg) + "\n").encode())
    await w_a.drain()

    line_b = await r_b.readline()
    msg_b = json.loads(line_b.decode())
    while msg_b.get("protocol") != "/chat/channel/1.0.0":
        line_b = await r_b.readline()
        msg_b = json.loads(line_b.decode())

    ch_data = msg_b["data"]
    dec_ch = decrypt_channel_message(ch_data["encryptedData"], channel_key)
    assert dec_ch == ch_text
    print(f'✅ Encrypted Channel Message on {channel_name} received and decrypted: "{dec_ch}"\n')

    # 6. Key Revocation Check
    print("   Revoking Node A's key on blockchain...")
    rev_res = await chain_b.revoke_key(node_a_id, RevocationReason.KEY_COMPROMISE, keys_a["privateKey"])
    assert rev_res["success"] is True

    verify_check = await chain_b.verify_key(node_a_id, keys_a["publicKey"])
    assert verify_check["isRevoked"] is True
    print(f"   Node A On-Chain Status on Node B: {verify_check['status']} (Revoked={verify_check['isRevoked']})")
    print("✅ Revoked key successfully rejected and quarantined!\n")

    # Cleanup
    w_a.close()
    w_b.close()
    server.close()
    await server.wait_closed()

    print("================================================================")
    print(" 🎉 ALL MULTI-NODE NETWORK & SECURITY TESTS PASSED (100%)")
    print("================================================================")


if __name__ == "__main__":
    asyncio.run(run_network_e2e_test())
