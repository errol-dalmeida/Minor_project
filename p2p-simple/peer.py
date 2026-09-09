import asyncio
from datetime import datetime
import json
import os
import random
import string
import sys
import time
from typing import Dict, Set, Optional

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

# ── RELAY ADDRESS ────────────────────────────────────────────────
BOOTSTRAP_ADDR = os.environ.get("RELAY_ADDR", "127.0.0.1:4001")
if ":" in BOOTSTRAP_ADDR:
    RELAY_HOST, RELAY_PORT_STR = BOOTSTRAP_ADDR.split(":")[:2]
    RELAY_PORT = int(RELAY_PORT_STR)
else:
    RELAY_HOST = "127.0.0.1"
    RELAY_PORT = 4001
RELAY_ID = os.environ.get("RELAY_ID", "12D3KooWDrVXBueH62aGpGxdeYU8AJFUT6n38xfmNMRXydtk682S")

# Step 1: Generate ECDSA keypair + DID for this peer
keypair = generate_key_pair()
privateKey = keypair["privateKey"]
publicKey = keypair["publicKey"]

# Step 2: In-memory network state & trust database
trustScores: Dict[str, int] = {}       # peerId -> score (0-100)
keyRegistry: Dict[str, str] = {}       # peerId -> publicKeyHex
peers: Set[str] = set()                # active connected peer IDs
lastSeen: Dict[str, float] = {}        # peerId -> timestamp
revokedPeers: Set[str] = set()         # peerIds revoked on-chain

# Channels State
joinedChannels: Set[str] = {"#general"}
channelKeys: Dict[str, str] = {"#general": sha256("public-general-channel-salt")}
channelMembers: Dict[str, Set[str]] = {"#general": set()}
activeChannel = "#general"

# Step 3: Initialize Native In-Code P2P Blockchain
blockchain = NativeBlockchain()

# Peer ID (matching libp2p multihash style)
MY_ID = os.environ.get("PEER_ID") or ("12D3KooW" + "".join(random.choices(string.ascii_letters + string.digits, k=44)))
MY_DID = create_did(MY_ID, publicKey)

try:
    with open(f"did-{MY_ID[:8]}.json", "w", encoding="utf-8") as f:
        json.dump(MY_DID, f, indent=2)
except Exception:
    pass

# Relay connection stream
relay_writer: Optional[asyncio.StreamWriter] = None


async def send_routed_msg(protocol: str, target: str, data: dict):
    if not relay_writer:
        return
    envelope = {
        "type": "ROUTED_MSG",
        "protocol": protocol,
        "sender": MY_ID,
        "target": target,
        "data": data
    }
    try:
        line = json.dumps(envelope) + "\n"
        relay_writer.write(line.encode("utf-8"))
        await relay_writer.drain()
    except Exception:
        pass


# ────────────────────────────────────────────────────────────────
# Blockchain P2P Protocols & Synchronization Helpers
# ────────────────────────────────────────────────────────────────

async def announce_did(peer_id: str):
    tx = Transaction(
        type=TransactionType.REGISTER_KEY,
        senderPeerId=MY_ID,
        payload={"publicKeyHex": publicKey, "didUri": MY_DID["id"]}
    )
    tx.sign(privateKey)
    payload = {
        "peerId": MY_ID,
        "did": MY_DID,
        "publicKey": publicKey,
        "regTx": tx.to_dict()
    }
    await send_routed_msg("/did/1.0.0", peer_id, payload)


async def sync_blockchain_with_peer(peer_id: str):
    await send_routed_msg("/chain/sync/1.0.0", peer_id, {"type": "GET_CHAIN"})


async def broadcast_transaction(tx: Transaction):
    await send_routed_msg("/chain/tx/1.0.0", "*", tx.to_dict())


async def announce_channel_action(channel: str, action: str = "JOIN"):
    await send_routed_msg("/channel/join/1.0.0", "*", {
        "peerId": MY_ID,
        "channel": channel,
        "action": action
    })


# 1. Send E2EE Direct Message (ECIES)
async def send_direct_message(recipient_peer_id: str, message_text: str):
    target_key = keyRegistry.get(recipient_peer_id)
    on_chain_record = await blockchain.resolve_key(recipient_peer_id)
    if on_chain_record and on_chain_record.get("publicKeyHex"):
        target_key = on_chain_record["publicKeyHex"]

    if not target_key:
        print(f"❌ Cannot send DM: Recipient {recipient_peer_id[:16]}... public key not found on blockchain or gossip.")
        return

    if on_chain_record and on_chain_record.get("isRevoked"):
        print(f"🚫 Cannot send DM: Recipient {recipient_peer_id[:16]}... has a REVOKED key on-chain!")
        return

    # 1. Asymmetric ECIES Encryption
    encrypted_data = encrypt_ecc(message_text, target_key, privateKey)
    timestamp = int(time.time() * 1000)

    # 2. ECDSA Signature over Ciphertext Envelope
    sig_payload = f"{encrypted_data['ciphertext']}:{encrypted_data['iv']}:{encrypted_data['tag']}:{timestamp}"
    signature = sign_message(sig_payload, privateKey)

    payload = {
        "from": MY_ID,
        "to": recipient_peer_id,
        "encryptedData": encrypted_data,
        "signature": signature,
        "timestamp": timestamp
    }

    await send_routed_msg("/chat/dm/1.0.0", recipient_peer_id, payload)
    print(f"🔒 [DM SENT] Encrypted with ECIES (ECC) & signed for {recipient_peer_id[:16]}...")
    print(f'   💬 "{message_text}"')


# 2. Send Group Channel Message
async def send_channel_message(channel: str, message_text: str):
    if channel not in joinedChannels:
        print(f'❌ You have not joined {channel}. Type "join {channel}" first.')
        return

    channel_key = channelKeys.get(channel)
    if not channel_key:
        channel_key = sha256(f"channel-key-salt-{channel}")
        channelKeys[channel] = channel_key

    # 1. Encrypt with Channel Key
    encrypted_data = encrypt_channel_message(message_text, channel_key)
    timestamp = int(time.time() * 1000)

    # 2. ECDSA Signature
    sig_payload = f"{channel}:{encrypted_data['ciphertext']}:{encrypted_data['iv']}:{encrypted_data['tag']}:{timestamp}"
    signature = sign_message(sig_payload, privateKey)

    payload = {
        "channel": channel,
        "from": MY_ID,
        "encryptedData": encrypted_data,
        "signature": signature,
        "timestamp": timestamp
    }

    target_count = len([p for p in peers if p not in revokedPeers])
    await send_routed_msg("/chat/channel/1.0.0", "*", payload)
    print(f'📢 [CHANNEL {channel}] Sent encrypted message to {target_count} peer(s): "{message_text}"')


# 3. Send Broadcast Message
async def send_broadcast(message_text: str):
    signature = sign_message(message_text, privateKey)
    payload = {
        "from": MY_ID,
        "message": message_text,
        "signature": signature
    }
    target_count = len([p for p in peers if p not in revokedPeers])
    await send_routed_msg("/chat/1.0.0", "*", payload)
    print(f"📤 Broadcasted signed message to {target_count} peer(s)")


# ────────────────────────────────────────────────────────────────
# Protocol Message Handlers
# ────────────────────────────────────────────────────────────────

async def handle_did_protocol(sender: str, data: dict):
    peer_id = data.get("peerId")
    did = data.get("did") or {}
    their_key = data.get("publicKey")
    reg_tx = data.get("regTx")

    if not peer_id or not their_key:
        return

    keyRegistry[peer_id] = their_key

    if reg_tx:
        blockchain.add_transaction(Transaction.from_dict(reg_tx))
    elif peer_id not in blockchain.state:
        blockchain.state[peer_id] = {
            "peerId": peer_id,
            "publicKeyHex": their_key,
            "didUri": did.get("id") or f"did:peer:{peer_id}",
            "isRevoked": False,
            "reason": RevocationReason.NONE,
            "createdAt": int(time.time() * 1000),
            "updatedAt": int(time.time() * 1000),
            "revokedAt": 0
        }

    on_chain_record = await blockchain.resolve_key(peer_id)
    if on_chain_record and on_chain_record.get("isRevoked"):
        revokedPeers.add(peer_id)
        trustScores[peer_id] = 0
        print(f"\n🚨 [DPKI] Received DID from {peer_id[:16]}... but key is REVOKED on-chain!")
    elif peer_id not in trustScores:
        trustScores[peer_id] = 50
        print(f"\n🆔 DID received from: {peer_id[:16]}...")
        print(f"   DID   : {did.get('id', f'did:peer:{peer_id}')}")
        print(f"   Status: {'✅ On-Chain Registered' if on_chain_record else '⚠️  Unregistered On-Chain'}")
        print(f"   Trust : 50/100")


async def handle_dm_protocol(sender: str, data: dict):
    from_peer = data.get("from", sender)
    to_peer = data.get("to")
    encrypted_data = data.get("encryptedData")
    signature = data.get("signature")
    timestamp = data.get("timestamp")

    if to_peer != MY_ID or not encrypted_data:
        return

    # 1. Check On-Chain Revocation Status
    on_chain_check = await blockchain.verify_key(from_peer, keyRegistry.get(from_peer, ""))
    if on_chain_check.get("isRevoked") or from_peer in revokedPeers:
        trustScores[from_peer] = 0
        print(f"\n🚫 [BLOCKED DM - REVOKED KEY] Direct message from {from_peer[:16]}... REJECTED.")
        return

    # 2. Resolve sender public key
    sender_key = keyRegistry.get(from_peer)
    on_chain_data = await blockchain.resolve_key(from_peer)
    if on_chain_data and on_chain_data.get("publicKeyHex"):
        sender_key = on_chain_data["publicKeyHex"]

    if not sender_key:
        print(f"\n⚠️  [DM] Direct message from {from_peer[:16]}... discarded (unknown public key).")
        return

    # 3. Verify Signature over Ciphertext
    sig_payload = f"{encrypted_data['ciphertext']}:{encrypted_data['iv']}:{encrypted_data['tag']}:{timestamp}"
    valid_sig = verify_message(sig_payload, signature, sender_key)

    if not valid_sig:
        current = trustScores.get(from_peer, 50)
        nxt = max(0, current - 25)
        trustScores[from_peer] = nxt
        print(f"\n❌ [DM - BAD SIGNATURE] Direct message from {from_peer[:16]}... failed signature check!")
        return

    # 4. Decrypt with Asymmetric ECC (ECIES)
    try:
        decrypted_text = decrypt_ecc(encrypted_data, sender_key, privateKey)
    except Exception:
        print(f"\n❌ [DM - DECRYPTION FAILED] Could not decrypt message from {from_peer[:16]}...")
        return

    # 5. Update trust score
    current = trustScores.get(from_peer, 50)
    nxt = min(100, current + 5)
    trustScores[from_peer] = nxt
    lastSeen[from_peer] = time.time()

    print(f"\n🔒 [CONFIDENTIAL 1-on-1 DM] from {from_peer[:16]}...:")
    print(f'   💬 "{decrypted_text}"')
    print(f"   🔐 ECIES Decrypted | ✅ On-Chain Verified (Trust: {current} → {nxt})")


async def handle_channel_protocol(sender: str, data: dict):
    channel = data.get("channel")
    from_peer = data.get("from", sender)
    encrypted_data = data.get("encryptedData")
    signature = data.get("signature")
    timestamp = data.get("timestamp")

    if channel not in joinedChannels or not encrypted_data:
        return

    # 1. Check On-Chain Revocation Status
    on_chain_check = await blockchain.verify_key(from_peer, keyRegistry.get(from_peer, ""))
    if on_chain_check.get("isRevoked") or from_peer in revokedPeers:
        trustScores[from_peer] = 0
        print(f"\n🚫 [BLOCKED CHANNEL - REVOKED KEY] Message in {channel} from {from_peer[:16]}... REJECTED.")
        return

    # 2. Resolve sender public key
    sender_key = keyRegistry.get(from_peer)
    on_chain_data = await blockchain.resolve_key(from_peer)
    if on_chain_data and on_chain_data.get("publicKeyHex"):
        sender_key = on_chain_data["publicKeyHex"]

    if not sender_key:
        return

    # 3. Verify Signature
    sig_payload = f"{channel}:{encrypted_data['ciphertext']}:{encrypted_data['iv']}:{encrypted_data['tag']}:{timestamp}"
    valid_sig = verify_message(sig_payload, signature, sender_key)
    if not valid_sig:
        current = trustScores.get(from_peer, 50)
        trustScores[from_peer] = max(0, current - 25)
        print(f"\n❌ [{channel} - BAD SIGNATURE] Message from {from_peer[:16]}... signature invalid!")
        return

    # 4. Decrypt Channel Message
    channel_key = channelKeys.get(channel)
    if not channel_key:
        return

    try:
        decrypted_text = decrypt_channel_message(encrypted_data, channel_key)
    except Exception:
        print(f"\n❌ [{channel}] Decryption failed for message from {from_peer[:16]}...")
        return

    current = trustScores.get(from_peer, 50)
    nxt = min(100, current + 3)
    trustScores[from_peer] = nxt
    lastSeen[from_peer] = time.time()

    print(f"\n📢 [CHANNEL {channel}] {from_peer[:16]}...:")
    print(f'   💬 "{decrypted_text}"')
    print(f"   🔐 Channel Encrypted | ✅ Verified (Trust: {current} → {nxt})")


async def handle_channel_join_protocol(sender: str, data: dict):
    peer_id = data.get("peerId", sender)
    channel = data.get("channel")
    action = data.get("action")

    if not channel:
        return

    members = channelMembers.setdefault(channel, set())
    if action == "JOIN":
        members.add(peer_id)
        print(f"\n👥 [Channel {channel}] Peer {peer_id[:16]}... joined channel. ({len(members)} members)")
    elif action == "LEAVE":
        members.discard(peer_id)
        print(f"\n👥 [Channel {channel}] Peer {peer_id[:16]}... left channel.")


async def handle_broadcast_protocol(sender: str, data: dict):
    from_peer = data.get("from", sender)
    message = data.get("message", "")
    signature = data.get("signature")

    # 1. Check On-Chain Revocation Status
    on_chain_check = await blockchain.verify_key(from_peer, keyRegistry.get(from_peer, ""))
    if on_chain_check.get("isRevoked") or from_peer in revokedPeers:
        trustScores[from_peer] = 0
        print(f"\n🚫 [BLOCKED BROADCAST] Message from {from_peer[:16]}... REJECTED (Revoked Key).")
        return

    # 2. Resolve Public Key
    sender_key = keyRegistry.get(from_peer)
    if on_chain_check.get("isValid"):
        on_chain_data = await blockchain.resolve_key(from_peer)
        if on_chain_data and on_chain_data.get("publicKeyHex"):
            sender_key = on_chain_data["publicKeyHex"]

    if not sender_key:
        print(f"\n⚠️  Broadcast from {from_peer[:16]}... — no public key registered.")
        return

    # 3. Verify Signature
    valid = verify_message(message, signature, sender_key)
    current = trustScores.get(from_peer, 50)
    lastSeen[from_peer] = time.time()

    if valid:
        nxt = min(100, current + 2)
        trustScores[from_peer] = nxt
        print(f"\n📢 [BROADCAST] {from_peer[:16]}...: {message}")
        print(f"   Trust: {current} → {nxt} | ✅ Verified")
    else:
        nxt = max(0, current - 25)
        trustScores[from_peer] = nxt
        print(f"\n📢 [❌ BAD SIGNATURE] Broadcast from {from_peer[:16]}... failed signature check!")


async def handle_chain_tx_protocol(sender: str, data: dict):
    try:
        tx = Transaction.from_dict(data)
        res = blockchain.add_transaction(tx)
        if res.get("success"):
            print(f"⛓️  [Blockchain] Processed on-chain transaction [{tx.type}] from {tx.senderPeerId[:16]}...")
    except Exception:
        pass


async def handle_chain_sync_protocol(sender: str, data: dict):
    msg_type = data.get("type")
    if msg_type == "GET_CHAIN":
        response = {
            "type": "CHAIN_RESPONSE",
            "chain": [b.to_dict() for b in blockchain.chain]
        }
        await send_routed_msg("/chain/sync/1.0.0", sender, response)
    elif msg_type == "CHAIN_RESPONSE":
        new_chain = data.get("chain", [])
        if isinstance(new_chain, list) and len(new_chain) > len(blockchain.chain):
            replaced = blockchain.replace_chain(new_chain)
            if replaced:
                print(f"⛓️  [Blockchain Sync] Synchronized {len(new_chain)} blocks from {sender[:16]}...")


# ────────────────────────────────────────────────────────────────
# Relay Stream Reader Loop
# ────────────────────────────────────────────────────────────────

async def relay_listener(reader: asyncio.StreamReader):
    while True:
        line = await reader.readline()
        if not line:
            print("\n🔌 Disconnected from relay.")
            break
        try:
            msg = json.loads(line.decode("utf-8").strip())
        except Exception:
            continue

        mtype = msg.get("type")

        if mtype == "PEER_LIST":
            peer_list = msg.get("peers", [])
            for pid in peer_list:
                if pid != MY_ID and pid != RELAY_ID and pid not in peers:
                    peers.add(pid)
                    lastSeen[pid] = time.time()
                    print(f"\n🔗 Peer joined: {pid[:16]}... ({len(peers)} peer(s) connected)")
                    asyncio.create_task(on_peer_joined(pid))

        elif mtype == "PEER_JOINED":
            pid = msg.get("peerId")
            if pid and pid != MY_ID and pid != RELAY_ID:
                peers.add(pid)
                lastSeen[pid] = time.time()
                print(f"\n🔗 Peer joined: {pid[:16]}... ({len(peers)} peer(s) connected)")
                asyncio.create_task(on_peer_joined(pid))

        elif mtype == "PEER_LEFT":
            pid = msg.get("peerId")
            if pid in peers:
                peers.remove(pid)
                for members in channelMembers.values():
                    members.discard(pid)
                print(f"\n🔌 Peer left: {pid[:16]}... ({len(peers)} peer(s) remaining)")

        elif mtype == "ROUTED_MSG":
            proto = msg.get("protocol")
            sender = msg.get("sender")
            data = msg.get("data", {})

            if sender == MY_ID:
                continue

            if proto == "/did/1.0.0":
                await handle_did_protocol(sender, data)
            elif proto == "/chat/dm/1.0.0":
                await handle_dm_protocol(sender, data)
            elif proto == "/chat/channel/1.0.0":
                await handle_channel_protocol(sender, data)
            elif proto == "/channel/join/1.0.0":
                await handle_channel_join_protocol(sender, data)
            elif proto == "/chat/1.0.0":
                await handle_broadcast_protocol(sender, data)
            elif proto == "/chain/tx/1.0.0":
                await handle_chain_tx_protocol(sender, data)
            elif proto == "/chain/sync/1.0.0":
                await handle_chain_sync_protocol(sender, data)


async def on_peer_joined(peer_id: str):
    await asyncio.sleep(0.3)
    await announce_did(peer_id)
    await asyncio.sleep(0.2)
    for ch in list(joinedChannels):
        await announce_channel_action(ch, "JOIN")
    await asyncio.sleep(0.2)
    await sync_blockchain_with_peer(peer_id)


# ────────────────────────────────────────────────────────────────
# Diagnostic CLI Commands
# ────────────────────────────────────────────────────────────────

async def print_trust_scores():
    print("\n📊 Trust & Identity Scores:")
    if not trustScores:
        print("   (no peer interactions yet)\n")
        return

    for peer_id_raw, score in trustScores.items():
        peer_id = str(peer_id_raw)
        bar = "█" * (score // 10)
        empty = "░" * (10 - (score // 10))

        status_badge = "⚠️ UNREGISTERED"
        if peer_id in revokedPeers:
            status_badge = "🛑 REVOKED"
        else:
            on_chain = await blockchain.resolve_key(peer_id)
            if on_chain and not on_chain.get("isRevoked"):
                status_badge = "✅ ON-CHAIN VERIFIED"
            elif on_chain and on_chain.get("isRevoked"):
                status_badge = "🛑 REVOKED"

        print(f"   {peer_id[:16]}... [{bar}{empty}] {score}/100 | {status_badge}")
    print()


def print_channels():
    print("\n📡 Group Channels:")
    print(f"   Active Target Channel : {activeChannel}")
    print(f"   Joined Channels       : {', '.join(joinedChannels)}")
    print("\n👥 Channel Member Counts:")
    for ch, members in channelMembers.items():
        total = len(members) + (1 if ch in joinedChannels else 0)
        print(f"   {ch.ljust(12)}: {total} member(s)")
    print()


def print_blocks():
    print(f"\n⛓️  Native Blockchain State (Height: {len(blockchain.chain)} blocks):")
    for b in blockchain.chain:
        print(f"   [Block #{b.index}] Hash: {b.hash[:18]}... | Prev: {b.previousHash[:12]}... | Txs: {len(b.transactions)} | Nonce: {b.nonce}")
        for idx, tx in enumerate(b.transactions):
            print(f"      └─ Tx #{idx + 1}: [{tx.type}] Sender: {tx.senderPeerId[:14]}...")
    print()


def print_status():
    print("\n📡 Node, DPKI & Crypto Status:")
    print(f"   Peer ID     : {MY_ID}")
    print(f"   DID         : {MY_DID['id']}")
    print(f"   Public Key  : {publicKey[:32]}... (ECDSA prime256v1)")
    print(f"   E2EE Crypto : ECIES (ECDH + HKDF-SHA256 + AES-256-GCM)")
    print(f"   Blockchain  : 🟢 Native In-Code P2P Chain (Height: {len(blockchain.chain)})")
    print(f"   Registered  : {len(blockchain.get_all_registered_peers())} peer identities")
    print(f"   Active Chan : {activeChannel}")
    print(f"   Connected   : {len(peers)} peer(s)")
    print()


# ────────────────────────────────────────────────────────────────
# Interactive CLI Input Loop
# ────────────────────────────────────────────────────────────────

async def cli_loop():
    global activeChannel, privateKey, publicKey, MY_DID

    loop = asyncio.get_running_loop()

    while True:
        try:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            inp = line.strip()
            if not inp:
                continue

            # 1. Direct 1-on-1 Message: @peerId <message> or dm <peerId> <message>
            if inp.startswith("@") or inp.startswith("dm "):
                if inp.startswith("@"):
                    parts = inp[1:].split(" ", 1)
                    target = parts[0]
                    msg = parts[1] if len(parts) > 1 else ""
                else:
                    parts = inp.split(" ", 2)
                    target = parts[1] if len(parts) > 1 else ""
                    msg = parts[2] if len(parts) > 2 else ""

                if not target or not msg:
                    print("Usage: @<peerId> <message> or dm <peerId> <message>")
                    continue

                full_peer_id = next((p for p in peers if p.startswith(target)), None) or \
                               next((p for p in keyRegistry.keys() if p.startswith(target)), None) or \
                               target

                await send_direct_message(full_peer_id, msg)
                continue

            # 2. Channel Message: #channel <message>
            if inp.startswith("#"):
                parts = inp.split(" ", 1)
                ch = parts[0]
                msg = parts[1] if len(parts) > 1 else ""
                if not msg:
                    activeChannel = ch
                    if ch not in joinedChannels:
                        joinedChannels.add(ch)
                        channelKeys[ch] = sha256(f"channel-key-salt-{ch}")
                        await announce_channel_action(ch, "JOIN")
                    print(f"🎯 Switched active target channel to: {activeChannel}")
                    continue
                await send_channel_message(ch, msg)
                continue

            # 3. Join Channel: join #channel
            if inp.startswith("join "):
                parts = inp.split(" ")
                ch = parts[1] if len(parts) > 1 else ""
                if not ch.startswith("#"):
                    ch = "#" + ch
                joinedChannels.add(ch)
                if ch not in channelKeys:
                    channelKeys[ch] = sha256(f"channel-key-salt-{ch}")
                activeChannel = ch
                await announce_channel_action(ch, "JOIN")
                print(f"✅ Joined group channel: {ch} (Set as active target)")
                continue

            # 4. Leave Channel: leave #channel
            if inp.startswith("leave "):
                parts = inp.split(" ")
                ch = parts[1] if len(parts) > 1 else ""
                if not ch.startswith("#"):
                    ch = "#" + ch
                if ch == "#general":
                    print("Cannot leave default #general channel.")
                    continue
                joinedChannels.discard(ch)
                await announce_channel_action(ch, "LEAVE")
                if activeChannel == ch:
                    activeChannel = "#general"
                print(f"👋 Left group channel: {ch}")
                continue

            # 5. Blockchain & Diagnostic Commands
            if inp == "channels":
                print_channels()
            elif inp in ("blocks", "chain"):
                print_blocks()
            elif inp == "trust":
                await print_trust_scores()
            elif inp == "peers":
                print(f"\n👥 Connected peers: {len(peers)}")
                for pid in peers:
                    print(f"   {pid[:16]}...")
                print()
            elif inp == "status":
                print_status()
            elif inp == "register":
                res = await blockchain.register_key(MY_ID, publicKey, MY_DID["id"], privateKey)
                if res.get("success"):
                    await broadcast_transaction(res["transaction"])
                    print(f"✅ Key registered on native blockchain in Block #{res['block'].index}! Broadcasted to network.")
            elif inp == "revoke" or inp.startswith("revoke "):
                parts = inp.split()
                reason_code = RevocationReason.KEY_COMPROMISE
                if len(parts) > 1:
                    arg = parts[1].lower()
                    if arg in ("compromise", "1"):
                        reason_code = 1
                    elif arg in ("superseded", "2"):
                        reason_code = 2
                    elif arg in ("decommissioned", "3"):
                        reason_code = 3
                    elif arg in ("malicious", "4"):
                        reason_code = 4
                    elif arg.isdigit():
                        p = int(arg)
                        if 1 <= p <= 4:
                            reason_code = p

                res = await blockchain.revoke_key(MY_ID, reason_code, privateKey)
                if res.get("success"):
                    revokedPeers.add(MY_ID)
                    await broadcast_transaction(res["transaction"])
                    print(f"🛑 Key marked REVOKED on native blockchain! Broadcasted to network. Reason code: {reason_code}")
            elif inp == "unrevoke":
                res = await blockchain.unrevoke_key(MY_ID, privateKey)
                if res.get("success"):
                    revokedPeers.discard(MY_ID)
                    await broadcast_transaction(res["transaction"])
                    print("♻️  Key UNREVOKED & REINSTATED on native blockchain! Broadcasted to network.")
            elif inp == "rotate":
                if MY_ID in revokedPeers:
                    print("❌ Cannot rotate: This identity is REVOKED on-chain.")
                    continue
                print("🔄 Generating new ECDSA keypair...")
                new_keypair = generate_key_pair()
                new_did = create_did(MY_ID, new_keypair["publicKey"])
                res = await blockchain.rotate_key(MY_ID, new_keypair["publicKey"], new_did["id"], privateKey)
                if res.get("success"):
                    privateKey = new_keypair["privateKey"]
                    publicKey = new_keypair["publicKey"]
                    MY_DID = new_did
                    with open(f"did-{MY_ID[:8]}.json", "w", encoding="utf-8") as f:
                        json.dump(MY_DID, f, indent=2)
                    await broadcast_transaction(res["transaction"])
                    print(f"✅ Key rotated on native blockchain! Broadcasted to network. New PubKey: {publicKey[:24]}...")
                else:
                    print(f"❌ Key rotation failed: {res.get('error')}")
            elif inp.startswith("lookup"):
                parts = inp.split()
                target = parts[1] if len(parts) > 1 else ""
                if not target:
                    print("Usage: lookup <peerId>")
                    continue
                full_peer_id = next((p for p in blockchain.state.keys() if p.startswith(target)), target)
                rec = await blockchain.resolve_key(full_peer_id)
                if not rec:
                    print(f"❌ No record found on blockchain for {target}")
                else:
                    print("📄 Native Blockchain Record:")
                    print(f"   Peer ID       : {rec.get('peerId')}")
                    print(f"   DID URI       : {rec.get('didUri')}")
                    print(f"   Public Key    : {rec.get('publicKeyHex', '')[:32]}...")
                    print(f"   Status        : {'🛑 REVOKED' if rec.get('isRevoked') else '✅ ACTIVE'}")
                    if rec.get("isRevoked"):
                        print(f"   Reason Code   : {rec.get('reason')}")
                    created_dt = datetime.fromtimestamp(rec.get("createdAt", 0) / 1000).strftime("%Y-%m-%d %H:%M:%S")
                    updated_dt = datetime.fromtimestamp(rec.get("updatedAt", 0) / 1000).strftime("%Y-%m-%d %H:%M:%S")
                    print(f"   Registered At : {created_dt}")
                    print(f"   Updated At    : {updated_dt}")
                    hist = blockchain.get_key_history(full_peer_id)
                    print(f"   Key History   : {len(hist)} key version(s)")
            else:
                if activeChannel and activeChannel != "#general":
                    await send_channel_message(activeChannel, inp)
                else:
                    await send_broadcast(inp)

        except (asyncio.CancelledError, KeyboardInterrupt):
            break
        except Exception as e:
            print(f"⚠️ Error: {e}")


async def main():
    global relay_writer

    print("\n================================================================")
    print(" 🚀 P2P NODE STARTED (Native Blockchain + ECC Asymmetric Crypto)")
    print("================================================================")
    print(f"Peer ID        : {MY_ID}")
    print(f"DID            : {MY_DID['id']}")
    print(f"Public Key     : {publicKey[:32]}...")
    print(f"Active Channel : {activeChannel}")
    print(f"Joined Channels: {', '.join(joinedChannels)}")
    print(f"Relay Bootstrap: {RELAY_HOST}:{RELAY_PORT}")
    print("\nCommands:")
    print("  @<peerId> <msg>     - Send End-to-End Encrypted (ECIES) Direct Message")
    print("  #<channel> <msg>    - Send Encrypted Message to specific Group Channel")
    print(f"  <message>           - Send message to active channel ({activeChannel})")
    print("  join <#channel>     - Join/Create a custom group channel")
    print("  leave <#channel>    - Leave a group channel")
    print("  channels            - List joined channels & member counts")
    print("  register            - Register/update identity on native blockchain")
    print("  revoke [reason]     - Revoke current key on-chain (1:Compromised, 2:Superseded, 3:Decommissioned, 4:Malicious)")
    print("  unrevoke            - Reinstate revoked key on-chain")
    print("  rotate              - Generate new keypair and rotate on-chain")
    print("  lookup <peerId>     - Query blockchain record & key history")
    print("  blocks / chain      - View local blockchain height & block details")
    print("  trust               - Show trust scores and verification badges")
    print("  peers               - Show connected peer list")
    print("  status              - Show node, DPKI, and channel status")
    print("  Ctrl+C              - Exit\n")

    # Register own key on native blockchain
    print(f"⛓️  [Native Blockchain] Registering genesis identity for {MY_ID[:16]}...")
    reg_result = await blockchain.register_key(MY_ID, publicKey, MY_DID["id"], privateKey)
    if reg_result.get("success"):
        b = reg_result["block"]
        print(f"✅ [Blockchain] Identity registered in Block #{b.index}! Hash: {b.hash[:18]}...")

    # Subscribe to internal blockchain events
    def on_revoked(data):
        pid = str(data.get("peerId"))
        revokedPeers.add(pid)
        trustScores[pid] = 0
        print(f"\n🚨 [BLOCKCHAIN EVENT] Peer {pid[:16]}... was REVOKED on-chain! (Reason code: {data.get('reason')})")
        print("   Trust set to 0. All subsequent communications quarantined.")

    def on_unrevoked(data):
        pid = str(data.get("peerId"))
        revokedPeers.discard(pid)
        trustScores[pid] = 50
        print(f"\n♻️  [BLOCKCHAIN EVENT] Peer {pid[:16]}... was REINSTATED on-chain!")
        print("   Trust restored to 50/100.")

    def on_rotated(data):
        pid = str(data.get("peerId"))
        keyRegistry[pid] = data.get("newKey")
        revokedPeers.discard(pid)
        print(f"\n🔄 [BLOCKCHAIN EVENT] Peer {pid[:16]}... rotated public key on-chain!")

    def on_registered(data):
        pid = str(data.get("peerId"))
        keyRegistry[pid] = data.get("publicKeyHex")
        if pid not in trustScores:
            trustScores[pid] = 50
        print(f"\n🆔 [BLOCKCHAIN EVENT] Peer {pid[:16]}... registered key on-chain.")

    blockchain.subscribe_events({
        "onKeyRevoked": on_revoked,
        "onKeyUnrevoked": on_unrevoked,
        "onKeyRotated": on_rotated,
        "onKeyRegistered": on_registered
    })

    # Connect to Relay
    try:
        reader, writer = await asyncio.open_connection(RELAY_HOST, RELAY_PORT)
        relay_writer = writer
        print("🔗 Connected to relay")

        # Handshake
        reg_payload = {"type": "REGISTER_PEER", "peerId": MY_ID}
        writer.write((json.dumps(reg_payload) + "\n").encode("utf-8"))
        await writer.drain()

        listener_task = asyncio.create_task(relay_listener(reader))
        cli_task = asyncio.create_task(cli_loop())

        await asyncio.gather(listener_task, cli_task)

    except ConnectionRefusedError:
        print(f"⚠️  Could not connect to relay at {RELAY_HOST}:{RELAY_PORT}. Running in standalone mode.")
        await cli_loop()
    except Exception as e:
        print(f"Relay connection stopped: {e}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nNode shutting down.")
