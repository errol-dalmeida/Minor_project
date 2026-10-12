import asyncio
import json
import os
import socket
import sys
from typing import Dict

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

RELAY_PORT = int(os.environ.get("RELAY_PORT", 4001))
RELAY_HOST = os.environ.get("RELAY_HOST", "0.0.0.0")
RELAY_ID = os.environ.get("RELAY_ID", "12D3KooWDrVXBueH62aGpGxdeYU8AJFUT6n38xfmNMRXydtk682S")

active_peers: Dict[str, asyncio.StreamWriter] = {}


async def send_msg(writer: asyncio.StreamWriter, data: dict):
    try:
        line = json.dumps(data) + "\n"
        writer.write(line.encode("utf-8"))
        await writer.drain()
    except Exception:
        pass


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer_id = None
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            try:
                msg = json.loads(line.decode("utf-8").strip())
            except Exception:
                continue

            msg_type = msg.get("type")

            if msg_type == "REGISTER_PEER":
                peer_id = msg.get("peerId")
                if peer_id:
                    old_writer = active_peers.get(peer_id)
                    if old_writer and old_writer != writer:
                        try:
                            old_writer.close()
                        except Exception:
                            pass
                    existing_peers = [p for p in active_peers.keys() if p != peer_id]
                    active_peers[peer_id] = writer
                    print(f"🔗 Peer connected: {peer_id}")

                    # 1. Send current peer list to newcomer
                    await send_msg(writer, {
                        "type": "PEER_LIST",
                        "peers": existing_peers
                    })

                    # 2. Announce new peer to existing peers
                    for pid, w in list(active_peers.items()):
                        if pid != peer_id:
                            asyncio.create_task(send_msg(w, {
                                "type": "PEER_JOINED",
                                "peerId": peer_id
                            }))

            elif msg_type == "ROUTED_MSG":
                if not peer_id or active_peers.get(peer_id) != writer:
                    continue
                target = msg.get("target")
                sender = peer_id
                msg["sender"] = sender

                if target == "*" or target == "broadcast":
                    for pid, w in list(active_peers.items()):
                        if pid != sender:
                            asyncio.create_task(send_msg(w, msg))
                elif target in active_peers:
                    asyncio.create_task(send_msg(active_peers[target], msg))

    except Exception:
        pass
    finally:
        if peer_id and active_peers.get(peer_id) == writer:
            del active_peers[peer_id]
            print(f"🔌 Peer left:     {peer_id}")
            for pid, w in list(active_peers.items()):
                asyncio.create_task(send_msg(w, {
                    "type": "PEER_LEFT",
                    "peerId": peer_id
                }))
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def get_local_ips():
    ips = ["127.0.0.1"]
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if ":" not in ip and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


async def main():
    server = await asyncio.start_server(handle_client, RELAY_HOST, RELAY_PORT)
    print("✅ Relay running")
    print(f"Peer ID: {RELAY_ID}")
    for ip in get_local_ips():
        print(f"/ip4/{ip}/tcp/{RELAY_PORT}/p2p/{RELAY_ID}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nRelay stopped.")
