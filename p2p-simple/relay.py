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
peer_directory: Dict[str, dict] = {}


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
                candidate = msg.get("peerId")
                host = msg.get("listenHost")
                port = msg.get("listenPort")
                if (isinstance(candidate, str) and candidate and len(candidate) <= 256
                        and isinstance(host, str) and host and host not in ("0.0.0.0", "::")
                        and type(port) is int and 1 <= port <= 65535
                        and peer_id in (None, candidate)):
                    peer_id = candidate
                    old_writer = active_peers.get(peer_id)
                    if old_writer and old_writer != writer:
                        try:
                            old_writer.close()
                        except Exception:
                            pass
                    existing_peers = [
                        peer_directory[p] for p in active_peers
                        if p != peer_id and p in peer_directory
                    ]
                    active_peers[peer_id] = writer
                    peer_directory[peer_id] = {
                        "peerId": peer_id, "listenHost": host, "listenPort": port
                    }
                    print(f"🔎 Peer registered for discovery: {peer_id} at {host}:{port}")

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
                                **peer_directory[peer_id],
                            }))
                else:
                    await send_msg(writer, {
                        "type": "ERROR", "error": "A peer ID and direct listening address are required."
                    })
                    break

            elif msg_type == "ROUTED_MSG":
                # This process is a directory, never an application transport.
                await send_msg(writer, {
                    "type": "ERROR", "error": "Discovery only: send application messages directly to peers."
                })

    except Exception:
        pass
    finally:
        if peer_id and active_peers.get(peer_id) == writer:
            del active_peers[peer_id]
            peer_directory.pop(peer_id, None)
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
    print("✅ Relay running (peer discovery only; no message forwarding)")
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
