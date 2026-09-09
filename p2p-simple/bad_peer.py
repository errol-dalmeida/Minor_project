import asyncio
import json
import os
import random
import string
import sys
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
    sign_message
)
from blockchain import NativeBlockchain, Transaction, TransactionType, RevocationReason

BOOTSTRAP_ADDR = os.environ.get("RELAY_ADDR", "127.0.0.1:4001")
if ":" in BOOTSTRAP_ADDR:
    RELAY_HOST, RELAY_PORT_STR = BOOTSTRAP_ADDR.split(":")[:2]
    RELAY_PORT = int(RELAY_PORT_STR)
else:
    RELAY_HOST = "127.0.0.1"
    RELAY_PORT = 4001

keypair = generate_key_pair()
privateKey = keypair["privateKey"]
publicKey = keypair["publicKey"]

peers: Set[str] = set()
keyRegistry: Dict[str, str] = {}
blockchain = NativeBlockchain()

MY_ID = os.environ.get("PEER_ID") or ("12D3KooWAdversary" + "".join(random.choices(string.ascii_letters + string.digits, k=30)))
MY_DID = create_did(MY_ID, publicKey)

# Attack modes: 'forge', 'revoked', 'valid'
attackMode = "forge"

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


async def announce_did(peer_id: str):
    payload = {
        "peerId": MY_ID,
        "did": MY_DID,
        "publicKey": publicKey
    }
    await send_routed_msg("/did/1.0.0", peer_id, payload)


async def sync_blockchain_with_peer(peer_id: str):
    await send_routed_msg("/chain/sync/1.0.0", peer_id, {"type": "GET_CHAIN"})


async def send_to_all(message: str):
    if not peers:
        print("⚠️  No peers connected yet")
        return

    signature = ""
    if attackMode == "forge":
        signature = "30440220deadbeef00112233445566778899aabbccddeeff00112233445566778899aabb0220deadbeef00112233445566778899aabbccddeeff00112233445566778899aabb"
        print("😈 Attacking: Sending message with forged signature...")
    else:
        signature = sign_message(message, privateKey)
        if attackMode == "revoked":
            print("😈 Attacking: Sending message with cryptographically REVOKED key...")
        else:
            print("😇 Sending compliant signed message...")

    payload = {"message": message, "signature": signature, "from": MY_ID}
    await send_routed_msg("/chat/1.0.0", "*", payload)
    print(f"📤 Dispatched attack payload to {len(peers)} peer(s)")


async def relay_listener(reader: asyncio.StreamReader):
    while True:
        line = await reader.readline()
        if not line:
            break
        try:
            msg = json.loads(line.decode("utf-8").strip())
        except Exception:
            continue

        mtype = msg.get("type")
        if mtype == "PEER_LIST":
            for pid in msg.get("peers", []):
                if pid != MY_ID and pid not in peers:
                    peers.add(pid)
                    print(f"\n🔗 Peer joined: {pid[:16]}...")
                    asyncio.create_task(on_peer_connect(pid))
        elif mtype == "PEER_JOINED":
            pid = msg.get("peerId")
            if pid and pid != MY_ID:
                peers.add(pid)
                print(f"\n🔗 Peer joined: {pid[:16]}...")
                asyncio.create_task(on_peer_connect(pid))
        elif mtype == "PEER_LEFT":
            pid = msg.get("peerId")
            peers.discard(pid)
        elif mtype == "ROUTED_MSG":
            proto = msg.get("protocol")
            data = msg.get("data", {})
            sender = msg.get("sender")
            if proto == "/chat/1.0.0":
                print(f"\n📩 Received: {data.get('message')}")
            elif proto == "/did/1.0.0":
                keyRegistry[data.get("peerId")] = data.get("publicKey")
            elif proto == "/chain/sync/1.0.0":
                if data.get("type") == "GET_CHAIN":
                    resp = {"type": "CHAIN_RESPONSE", "chain": [b.to_dict() for b in blockchain.chain]}
                    await send_routed_msg("/chain/sync/1.0.0", sender, resp)


async def on_peer_connect(peer_id: str):
    await asyncio.sleep(0.4)
    await announce_did(peer_id)
    await asyncio.sleep(0.3)
    await sync_blockchain_with_peer(peer_id)


async def cli_loop():
    global attackMode
    loop = asyncio.get_running_loop()

    while True:
        try:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            inp = line.strip()
            if not inp:
                continue

            if inp.startswith("mode"):
                parts = inp.split()
                mode = parts[1] if len(parts) > 1 else ""
                if mode in ("forge", "revoked", "valid"):
                    attackMode = mode
                    if attackMode == "revoked":
                        print("⛓️  Revoking key on native blockchain...")
                        res = await blockchain.revoke_key(MY_ID, RevocationReason.KEY_COMPROMISE, privateKey)
                        if res.get("success"):
                            await send_routed_msg("/chain/tx/1.0.0", "*", res["transaction"].to_dict())
                        print("🛑 Key marked REVOKED on blockchain! Ready to test revoked-key attacks.")
                    print(f"✅ Attack mode switched to: {attackMode.upper()}")
                else:
                    print("Unknown mode. Options: forge, revoked, valid")
            elif inp == "peers":
                print(f"Connected peers: {len(peers)}")
            else:
                await send_to_all(inp)
        except (asyncio.CancelledError, KeyboardInterrupt):
            break
        except Exception as e:
            print(f"⚠️ Error: {e}")


async def main():
    global relay_writer

    # Initial register on native blockchain
    await blockchain.register_key(MY_ID, publicKey, MY_DID["id"], privateKey)

    print("\n================================================================")
    print(" ⚠️  ADVERSARY NODE STARTED (Attack Simulator)")
    print("================================================================")
    print(f"Peer ID    : {MY_ID}")
    print(f"Attack Mode: {attackMode.upper()}")
    print("\nCommands:")
    print("  <message>       - Send message using current attack mode")
    print("  mode forge      - Set attack mode to send corrupted signatures")
    print("  mode revoked    - Revoke key on blockchain and attempt sending messages")
    print("  mode valid      - Send valid signed messages")
    print("  peers           - Show connected peers\n")

    try:
        reader, writer = await asyncio.open_connection(RELAY_HOST, RELAY_PORT)
        relay_writer = writer
        print("🔗 Connected to relay")

        reg_payload = {"type": "REGISTER_PEER", "peerId": MY_ID}
        writer.write((json.dumps(reg_payload) + "\n").encode("utf-8"))
        await writer.drain()

        await asyncio.gather(
            asyncio.create_task(relay_listener(reader)),
            asyncio.create_task(cli_loop())
        )
    except ConnectionRefusedError:
        print(f"⚠️  Could not connect to relay at {RELAY_HOST}:{RELAY_PORT}.")
    except Exception as e:
        print(f"Adversary node stopped: {e}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nAdversary node stopped.")
