import asyncio
from datetime import datetime
import json
import os
import random
import string
import sys
import time
import uuid
from typing import Dict, Set, List, Optional, Callable, Any

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from crypto_modular import CryptoSuite, SHA256Provider, NISTP256Provider, AESGCMProvider
from crypto import create_did
from blockchain import NativeBlockchain, Transaction, TransactionType, RevocationReason

MAX_FRAME_BYTES = 4 * 1024 * 1024


class PeerNode:
    """
    Decentralized Sovereign Peer Node Engine.
    Exposes modular, code-first Python functions for all P2P operations.
    """
    def __init__(
        self,
        peer_id: Optional[str] = None,
        relay_host: Optional[str] = "127.0.0.1",
        relay_port: int = 4001,
        listen_host: str = "0.0.0.0",
        listen_port: int = 0,
        crypto_suite: Optional[CryptoSuite] = None,
        auto_register_blockchain: bool = True,
        identity_file: Optional[str] = None,
        advertise_host: Optional[str] = None,
        seed_peers: Optional[List[tuple]] = None,
    ):
        self.relay_host = relay_host
        self.relay_port = relay_port
        # Direct P2P listening address (0 = OS assigns a free port)
        self.listen_host = listen_host
        self.listen_port = listen_port          # actual port filled in after start()
        self.advertise_host = advertise_host
        self._advertise_host = advertise_host or (
            listen_host if listen_host not in ("0.0.0.0", "::") else None
        )
        self.seed_peers = list(seed_peers or [])
        self.crypto_suite = crypto_suite or CryptoSuite.default()
        self.identity_file = identity_file

        # Step 1: Load or Generate sovereign keypair & DID
        loaded = False
        if identity_file and os.path.exists(identity_file):
            try:
                with open(identity_file, "r", encoding="utf-8") as f:
                    id_data = json.load(f)
                    if id_data.get("peerId") and id_data.get("privateKey") and id_data.get("publicKey"):
                        self.peer_id = id_data["peerId"]
                        self.private_key = id_data["privateKey"]
                        self.public_key = id_data["publicKey"]
                        self.did = id_data.get("did") or create_did(self.peer_id, self.public_key)
                        loaded = True
            except Exception:
                pass

        if not loaded:
            self.keypair = self.crypto_suite.generate_keypair()
            self.private_key = self.keypair["privateKey"]
            self.public_key = self.keypair["publicKey"]
            self.peer_id = peer_id or ("12D3KooW" + "".join(random.choices(string.ascii_letters + string.digits, k=44)))
            self.did = create_did(self.peer_id, self.public_key)
            if self.identity_file:
                self._save_identity()

        # Step 2: Local Isolated State & Databases (Zero-Trust)
        self.blockchain = NativeBlockchain()
        self.trust_scores: Dict[str, int] = {}
        self.key_registry: Dict[str, str] = {}
        self.connected_peers: Set[str] = set()
        self.last_seen: Dict[str, float] = {}
        self.revoked_peers: Set[str] = set()

        # Channels
        self.joined_channels: Set[str] = {"#general"}
        self.channel_keys: Dict[str, str] = {"#general": self.get_channel_key("#general")}
        self.channel_members: Dict[str, Set[str]] = {"#general": set()}
        self.active_channel = "#general"

        # Local inboxes for logs and messages
        self.message_history: List[Dict[str, Any]] = []
        self.event_log: List[str] = []

        # On-Demand Lazy Revocation Cache (peerId -> {is_revoked, status, cached_at, ttl})
        self.revocation_cache: Dict[str, Dict[str, Any]] = {}
        self.metrics: Dict[str, int] = {
            "packets_sent_scoped": 0,
            "packets_received_revocation": 0,
            "cache_hits": 0,
            "cache_misses": 0
        }

        # Hookable callbacks for UI / Automation
        self.on_message_received: Optional[Callable[[Dict[str, Any]], None]] = None
        self.on_blockchain_event: Optional[Callable[[str, Dict[str, Any]], None]] = None
        self.on_peer_update: Optional[Callable[[], None]] = None
        self.on_peer_event: Optional[Callable[[str, str], None]] = None
        self.on_verification_event: Optional[Callable[[str], None]] = None

        self._relay_reader: Optional[asyncio.StreamReader] = None
        self._relay_writer: Optional[asyncio.StreamWriter] = None
        self._listener_task: Optional[asyncio.Task] = None
        self._background_tasks: Set[asyncio.Task] = set()
        self._pending_chain_syncs: Dict[str, Any] = {}
        self.chain_sync_timeout = 2.0
        self._registration_tx: Optional[Transaction] = None
        self._is_running = False
        self.auto_register_blockchain = auto_register_blockchain

        # ── Direct P2P mesh (Solution 2) ──────────────────────────
        # peer_id -> asyncio.StreamWriter for the direct socket to that peer
        self._peer_writers: Dict[str, asyncio.StreamWriter] = {}
        # peer_id -> (host, port) of that peer's direct listener
        self._peer_addresses: Dict[str, tuple] = {}
        self._peer_connection_ids: Dict[str, tuple] = {}
        self._dial_locks: Dict[Any, asyncio.Lock] = {}
        self._retry_at: Dict[Any, float] = {}
        self._retry_delay: Dict[Any, float] = {}
        self.heartbeat_interval = 5.0
        self.peer_timeout = 20.0
        # Our own inbound P2P listener server
        self._p2p_server: Optional[asyncio.AbstractServer] = None

        self._setup_blockchain_listeners()

    def get_channel_key(self, channel: str) -> str:
        ch_clean = channel.lstrip("#")
        return self.crypto_suite.hash(f"channel-key-{ch_clean}")

    def _setup_blockchain_listeners(self):
        def on_revoked(data):
            pid = str(data.get("peerId"))
            self._refresh_peer_state(pid)
            log_msg = f"🚨 [BLOCKCHAIN] Peer {pid[:16]}... REVOKED on-chain! Reason: {data.get('reason')}"
            self._log_event(log_msg)
            if self.on_blockchain_event:
                self.on_blockchain_event("onKeyRevoked", data)

        def on_unrevoked(data):
            pid = str(data.get("peerId"))
            self._refresh_peer_state(pid)
            log_msg = f"♻️  [BLOCKCHAIN] Peer {pid[:16]}... REINSTATED on-chain!"
            self._log_event(log_msg)
            if self.on_blockchain_event:
                self.on_blockchain_event("onKeyUnrevoked", data)

        def on_rotated(data):
            pid = str(data.get("peerId"))
            self._refresh_peer_state(pid)
            log_msg = f"🔄 [BLOCKCHAIN] Peer {pid[:16]}... rotated public key!"
            self._log_event(log_msg)
            if self.on_blockchain_event:
                self.on_blockchain_event("onKeyRotated", data)

        def on_registered(data):
            pid = str(data.get("peerId"))
            self._refresh_peer_state(pid)
            log_msg = f"🆔 [BLOCKCHAIN] Peer {pid[:16]}... registered key on-chain."
            self._log_event(log_msg)
            if self.on_blockchain_event:
                self.on_blockchain_event("onKeyRegistered", data)

        def on_block_added(data):
            b_dict = data.to_dict() if hasattr(data, "to_dict") else data
            idx = b_dict.get("index")
            h = str(b_dict.get("hash", ""))[:16]
            tx_count = len(b_dict.get("transactions", []))
            log_msg = f"📦 [BLOCKCHAIN] Block #{idx} appended! Hash: {h}... (Txs: {tx_count})"
            self._log_event(log_msg)
            if self.on_blockchain_event:
                self.on_blockchain_event("onBlockAdded", b_dict)

        def on_message_receipt(data):
            s = str(data.get("sender", ""))
            r = str(data.get("recipient", ""))
            mh = str(data.get("messageHash", ""))
            log_msg = f"📜 [BLOCKCHAIN] Message receipt anchored: {s[:16]}... ➔ {r[:16]}... (Hash: {mh[:16]}...)"
            self._log_event(log_msg)
            if self.on_blockchain_event:
                self.on_blockchain_event("onMessageReceipt", data)

        self.blockchain.subscribe_events({
            "onKeyRevoked": on_revoked,
            "onKeyUnrevoked": on_unrevoked,
            "onKeyRotated": on_rotated,
            "onKeyRegistered": on_registered,
            "onBlockAdded": on_block_added,
            "onMessageReceipt": on_message_receipt
        })

    def _log_event(self, text: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] {text}"
        self.event_log.append(entry)
        if len(self.event_log) > 200:
            self.event_log.pop(0)
        if self.on_verification_event and ("[LAZY CHECK]" in text or "verification unavailable" in text):
            self.on_verification_event(entry)

    # ─────────────────────────────────────────────────────────────
    # Lifecycle Methods
    # ─────────────────────────────────────────────────────────────

    async def start(self) -> bool:
        """Start an independent peer; bootstrap discovery is optional."""
        self._is_running = True

        if self.auto_register_blockchain:
            reg_res = await self.blockchain.register_key(
                self.peer_id, self.public_key, self.did["id"], self.private_key
            )
            if reg_res.get("success"):
                self._registration_tx = reg_res["transaction"]
                b = reg_res["block"]
                self._log_event(f"Identity registered on local chain in Block #{b.index}")

        try:
            self._p2p_server = await asyncio.start_server(
                self._handle_inbound_peer, self.listen_host, self.listen_port,
                limit=MAX_FRAME_BYTES,
            )
            sock = self._p2p_server.sockets[0]
            self.listen_port = sock.getsockname()[1]
        except Exception as e:
            self._is_running = False
            self._log_event(f"Could not start direct peer listener: {e}")
            return False
        self._log_event(f"Direct P2P listener running on {self.listen_host}:{self.listen_port}")
        self._start_background_task(self._maintain_peer_connections())
        if self.relay_host:
            self._listener_task = self._start_background_task(self._bootstrap_loop())
        return True

    def _listen_address(self, writer: Optional[asyncio.StreamWriter] = None) -> dict:
        """Use the actual LAN connection's interface, never an Internet probe."""
        host = self._advertise_host
        if writer and not self.advertise_host and self.listen_host in ("0.0.0.0", "::"):
            local = writer.get_extra_info("sockname")
            if local:
                host = local[0]
                self._advertise_host = host
        return {"peerId": self.peer_id, "listenHost": host or "127.0.0.1",
                "listenPort": self.listen_port}

    async def stop(self):
        """Cleanly disconnect from relay and close all direct peer connections."""
        self._is_running = False
        if self._p2p_server:
            self._p2p_server.close()
        tasks = set(self._background_tasks)
        if self._listener_task:
            tasks.add(self._listener_task)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for _, future in self._pending_chain_syncs.values():
            if not future.done():
                future.set_result(False)
        self._pending_chain_syncs.clear()

        # Close all direct peer connections
        for pid, w in list(self._peer_writers.items()):
            try:
                w.close()
                await w.wait_closed()
            except Exception:
                pass
        self._peer_writers.clear()
        self._peer_connection_ids.clear()
        self.connected_peers.clear()

        if self._p2p_server:
            self._p2p_server.close()
            try:
                await self._p2p_server.wait_closed()
            except Exception:
                pass
            self._p2p_server = None

        if self._relay_writer:
            try:
                self._relay_writer.close()
                await self._relay_writer.wait_closed()
            except Exception:
                pass
        self._relay_writer = None
        self._relay_reader = None
        self._log_event("Node stopped.")

    # ─────────────────────────────────────────────────────────────
    # Modular Cryptographic Suite Hot-Swapping
    # ─────────────────────────────────────────────────────────────

    def set_crypto_suite(self, new_suite: CryptoSuite):
        """Hot-swap the active cryptographic suite."""
        old_desc = self.crypto_suite.get_descriptor()
        self.crypto_suite = new_suite
        # Re-derive channel keys using new hashing algorithm if changed
        for ch in self.joined_channels:
            self.channel_keys[ch] = self.get_channel_key(ch)
        self._log_event(f"Crypto suite swapped: {old_desc} ➔ {new_suite.get_descriptor()}")

    # ─────────────────────────────────────────────────────────────
    # Core Function-Driven P2P Operations
    # ─────────────────────────────────────────────────────────────

    def get_active_contacts(self) -> Set[str]:
        """
        Interaction-Graph Scoping: Identify active contacts based on joined
        channel memberships, direct message history, and direct peer presence.
        """
        contacts = set()
        for ch in self.joined_channels:
            members = self.channel_members.get(ch, set())
            contacts.update(members)
        for msg in self.message_history:
            if msg.get("kind") not in ("INCOMING_DM", "OUTGOING_DM"):
                continue
            s = msg.get("sender")
            t = msg.get("target")
            if s and s != self.peer_id and not s.startswith("#") and s != "*":
                contacts.add(s)
            if t and t != self.peer_id and not t.startswith("#") and t != "*":
                contacts.add(t)
        for pid in self.last_seen.keys():
            if pid != self.peer_id:
                contacts.add(pid)
        contacts.discard(self.peer_id)
        return contacts

    async def verify_peer_revocation_lazy(
        self, peer_id: str, force_refresh: bool = False, ttl: float = 300.0
    ) -> Dict[str, Any]:
        """
        On-Demand Lazy Verification with Local TTL Caching.
        Avoids global broadcast storms by verifying revocation state only when needed.

        On cache miss, wait for a matching chain response from the target peer.
        Failed network refreshes must not produce a fresh ACTIVE cache entry.
        """
        now = time.time()
        cached = self.revocation_cache.get(peer_id)
        cache_ttl = min(ttl, cached.get("ttl", ttl)) if cached else ttl
        if not force_refresh and cached and (now - cached.get("cached_at", 0) < cache_ttl):
            self.metrics["cache_hits"] += 1
            return {
                "is_revoked": cached["is_revoked"],
                "status": cached["status"],
                "from_cache": True,
                "verified": cached.get("verified", cached["status"] in ("ACTIVE", "REVOKED", "ON_CHAIN_VERIFIED"))
            }

        self.metrics["cache_misses"] += 1

        # Running peers must obtain a direct reply before calling a cache
        # refresh verified. Offline/in-process ledger use remains supported.
        if self._is_running and peer_id != self.peer_id:
            if not await self._sync_chain_with_peer(peer_id):
                self.revocation_cache.pop(peer_id, None)
                self._log_event(f"⚠️ Lazy verification unavailable for {peer_id[:16]}... (chain refresh failed).")
                return {"is_revoked": peer_id in self.revoked_peers,
                        "status": "SYNC_UNAVAILABLE", "from_cache": False, "verified": False}

        # Step 2: Now check the (potentially updated) local chain
        on_chain = await self.blockchain.verify_key(peer_id, self.key_registry.get(peer_id, ""))
        is_rev = bool(on_chain.get("isRevoked"))
        verified = bool(on_chain.get("isValid") or is_rev)
        status = on_chain.get("status", "REVOKED" if is_rev else "ACTIVE")

        if is_rev:
            self.revoked_peers.add(peer_id)
            self.trust_scores[peer_id] = 0
        elif verified:
            was_revoked = peer_id in self.revoked_peers
            self.revoked_peers.discard(peer_id)
            if was_revoked:
                self.trust_scores[peer_id] = 50

        self.revocation_cache[peer_id] = {
            "is_revoked": is_rev,
            "status": status,
            "cached_at": time.time(),
            "ttl": ttl,
            "verified": verified,
            "updated_at": self.blockchain.state.get(peer_id, {}).get("updatedAt"),
            "public_key": self.key_registry.get(peer_id),
        }
        self._log_event(f"🔎 [LAZY CHECK] {peer_id[:16]}...: {status}")
        return {
            "is_revoked": is_rev,
            "status": status,
            "from_cache": False,
            "verified": verified
        }

    def _refresh_peer_state(self, peer_id: str):
        """Keep keys, quarantine state and existing cache entries consistent."""
        record = self.blockchain.state.get(peer_id)
        if not record:
            self.key_registry.pop(peer_id, None)
            self.revoked_peers.discard(peer_id)
            self.revocation_cache.pop(peer_id, None)
            return
        was_revoked = peer_id in self.revoked_peers
        self.key_registry[peer_id] = record["publicKeyHex"]
        is_revoked = bool(record.get("isRevoked"))
        if is_revoked:
            self.revoked_peers.add(peer_id)
            self.trust_scores[peer_id] = 0
        else:
            self.revoked_peers.discard(peer_id)
            if was_revoked or peer_id not in self.trust_scores:
                self.trust_scores[peer_id] = 50
        cached = self.revocation_cache.get(peer_id)
        if cached is not None or is_revoked:
            changed = (cached is None or cached.get("is_revoked") != is_revoked
                       or cached.get("updated_at") != record.get("updatedAt")
                       or cached.get("public_key") != record["publicKeyHex"])
            self.revocation_cache[peer_id] = {
                "is_revoked": is_revoked,
                "status": "REVOKED" if is_revoked else "ACTIVE",
                "cached_at": time.time() if changed else cached["cached_at"],
                "ttl": cached.get("ttl", 300.0) if cached else 300.0,
                "verified": True,
                "updated_at": record.get("updatedAt"),
                "public_key": record["publicKeyHex"],
            }

    def _resync_state_from_chain(self):
        """Update revoked_peers, trust_scores, key_registry, and revocation_cache from current blockchain state."""
        peer_ids = set(self.blockchain.state) | set(self.key_registry) | self.revoked_peers | set(self.revocation_cache)
        for pid in peer_ids:
            self._refresh_peer_state(pid)

    async def _sync_chain_with_peer(self, peer_id: str) -> bool:
        pending = self._pending_chain_syncs.get(peer_id)
        if pending:
            try:
                return await asyncio.wait_for(asyncio.shield(pending[1]), self.chain_sync_timeout)
            except asyncio.TimeoutError:
                return False
        request_id = uuid.uuid4().hex
        future = asyncio.get_running_loop().create_future()
        self._pending_chain_syncs[peer_id] = (request_id, future)
        self.metrics["chain_syncs_on_demand"] = self.metrics.get("chain_syncs_on_demand", 0) + 1
        try:
            sent = await self._send_routed("/chain/sync/1.0.0", peer_id,
                                           {"type": "GET_CHAIN", "requestId": request_id})
            if not sent:
                return False
            return await asyncio.wait_for(asyncio.shield(future), self.chain_sync_timeout)
        except asyncio.TimeoutError:
            self.metrics["chain_sync_timeouts"] = self.metrics.get("chain_sync_timeouts", 0) + 1
            return False
        finally:
            self._pending_chain_syncs.pop(peer_id, None)
            if not future.done():
                future.set_result(False)

    async def send_direct_message(self, recipient_id: str, message_text: str, anchor_on_chain: bool = True) -> Dict[str, Any]:
        """Send confidential 1-on-1 ECIES encrypted DM with on-demand lazy check and automatic on-chain receipt anchoring."""
        if self.peer_id in self.revoked_peers:
            err = "Cannot send DM: Your local identity is REVOKED on-chain."
            self._log_event(f"🚫 {err}")
            return {"success": False, "error": err}

        reachable = recipient_id in self.connected_peers
        if not reachable:
            return {"success": False, "error": "Recipient is unreachable (not connected)."}

        # 1. On-Demand Lazy Revocation Check
        lazy_check = await self.verify_peer_revocation_lazy(
            recipient_id, force_refresh=recipient_id in self.revoked_peers
        )
        if lazy_check.get("is_revoked"):
            err = f"Blocked DM: Recipient {recipient_id[:16]}... key is REVOKED on-chain."
            self._log_event(f"🚫 {err}")
            return {"success": False, "error": err}
        if not lazy_check.get("verified"):
            return {"success": False, "error": "Cannot verify recipient's current identity state."}
        if self.peer_id in self.revoked_peers:
            return {"success": False, "error": "Cannot send DM: Your identity became REVOKED during verification."}

        # 2. Resolve Recipient Public Key
        target_key = self.key_registry.get(recipient_id)
        on_chain = await self.blockchain.resolve_key(recipient_id)
        if on_chain and on_chain.get("publicKeyHex"):
            target_key = on_chain["publicKeyHex"]

        if not target_key:
            err = f"Cannot send DM: Recipient {recipient_id[:16]}... public key unknown."
            self._log_event(f"❌ {err}")
            return {"success": False, "error": err}

        # 2. Asymmetric ECIES Encryption
        encrypted_data = self.crypto_suite.encrypt_dm(message_text, target_key, self.private_key)
        timestamp = int(time.time() * 1000)

        # 3. ECDSA Signature
        sig_payload = f"{encrypted_data['ciphertext']}:{encrypted_data['iv']}:{encrypted_data['tag']}:{timestamp}"
        signature = self.crypto_suite.sign(sig_payload, self.private_key)

        receipt_info = None
        if anchor_on_chain:
            message_hash = self.crypto_suite.hash(sig_payload)
            receipt_res = await self.blockchain.commit_message_receipt(
                self.peer_id, recipient_id, message_hash, self.private_key, msg_type="DM"
            )
            if receipt_res.get("success"):
                await self._send_scoped_transaction(receipt_res["transaction"])
                b = receipt_res.get("block")
                receipt_info = {
                    "messageHash": message_hash,
                    "blockIndex": b.index if b else None,
                    "txHash": receipt_res.get("txHash"),
                    "target": recipient_id,
                    "msgType": "DM"
                }
                self._log_event(f"📜 DM receipt anchored to Block #{receipt_info['blockIndex']} (Hash: {message_hash[:16]}...)")

        payload = {
            "from": self.peer_id,
            "to": recipient_id,
            "encryptedData": encrypted_data,
            "signature": signature,
            "timestamp": timestamp,
            "receipt": receipt_info
        }

        if not await self._send_routed("/chat/dm/1.0.0", recipient_id, payload):
            return {"success": False, "error": "Direct peer connection unavailable; DM was not sent."}
        msg_hash = self.crypto_suite.hash(sig_payload)
        self._record_message("OUTGOING_DM", self.peer_id, recipient_id, message_text, "1-on-1 E2EE",
                             receipt=receipt_info, message_hash=msg_hash)
        self._log_event(f"🔒 Sent ECIES DM to {recipient_id[:16]}...: \"{message_text}\"")
        return {"success": True, "payload": payload, "receipt": receipt_info}

    async def send_channel_message(self, channel: str, message_text: str, anchor_on_chain: bool = True) -> Dict[str, Any]:
        """Send encrypted message to group channel with automatic on-chain receipt anchoring."""
        if self.peer_id in self.revoked_peers:
            return {"success": False, "error": "Cannot send channel message: Your identity is REVOKED."}
        if channel not in self.joined_channels:
            err = f"Must join {channel} before sending."
            self._log_event(f"❌ {err}")
            return {"success": False, "error": err}

        channel_key = self.channel_keys.get(channel) or self.get_channel_key(channel)
        self.channel_keys[channel] = channel_key

        encrypted_data = self.crypto_suite.encrypt_channel(message_text, channel_key)
        timestamp = int(time.time() * 1000)

        sig_payload = f"{channel}:{encrypted_data['ciphertext']}:{encrypted_data['iv']}:{encrypted_data['tag']}:{timestamp}"
        signature = self.crypto_suite.sign(sig_payload, self.private_key)

        receipt_info = None
        if anchor_on_chain:
            message_hash = self.crypto_suite.hash(sig_payload)
            receipt_res = await self.blockchain.commit_message_receipt(
                self.peer_id, channel, message_hash, self.private_key, msg_type="CHANNEL"
            )
            if receipt_res.get("success"):
                await self._send_scoped_transaction(receipt_res["transaction"])
                b = receipt_res.get("block")
                receipt_info = {
                    "messageHash": message_hash,
                    "blockIndex": b.index if b else None,
                    "txHash": receipt_res.get("txHash"),
                    "target": channel,
                    "msgType": "CHANNEL"
                }
                self._log_event(f"📜 Channel message receipt anchored to Block #{receipt_info['blockIndex']} (Hash: {message_hash[:16]}...)")

        payload = {
            "channel": channel,
            "from": self.peer_id,
            "encryptedData": encrypted_data,
            "signature": signature,
            "timestamp": timestamp,
            "receipt": receipt_info
        }

        if not await self._send_routed("/chat/channel/1.0.0", "*", payload):
            return {"success": False, "error": "No direct peer connection; channel message was not sent."}
        msg_hash = self.crypto_suite.hash(sig_payload)
        self._record_message("OUTGOING_CHANNEL", self.peer_id, channel, message_text, f"Channel {channel}",
                             receipt=receipt_info, message_hash=msg_hash)
        self._log_event(f"📢 Sent encrypted message to {channel}: \"{message_text}\"")
        return {"success": True, "payload": payload, "receipt": receipt_info}

    async def send_broadcast(self, message_text: str, anchor_on_chain: bool = True) -> Dict[str, Any]:
        """Send signed public broadcast message with automatic on-chain receipt anchoring."""
        if self.peer_id in self.revoked_peers:
            return {"success": False, "error": "Cannot broadcast: Your identity is REVOKED."}
        sig = self.crypto_suite.sign(message_text, self.private_key)
        timestamp = int(time.time() * 1000)
        sig_payload = f"{message_text}:{sig}"

        receipt_info = None
        if anchor_on_chain:
            message_hash = self.crypto_suite.hash(sig_payload)
            receipt_res = await self.blockchain.commit_message_receipt(
                self.peer_id, "*", message_hash, self.private_key, msg_type="BROADCAST"
            )
            if receipt_res.get("success"):
                await self._send_scoped_transaction(receipt_res["transaction"])
                b = receipt_res.get("block")
                receipt_info = {
                    "messageHash": message_hash,
                    "blockIndex": b.index if b else None,
                    "txHash": receipt_res.get("txHash"),
                    "target": "*",
                    "msgType": "BROADCAST"
                }
                self._log_event(f"📜 Broadcast receipt anchored to Block #{receipt_info['blockIndex']} (Hash: {message_hash[:16]}...)")

        payload = {
            "from": self.peer_id,
            "message": message_text,
            "signature": sig,
            "timestamp": timestamp,
            "receipt": receipt_info
        }
        if not await self._send_routed("/chat/1.0.0", "*", payload):
            return {"success": False, "error": "No direct peer connection; broadcast was not sent."}
        msg_hash = self.crypto_suite.hash(sig_payload)
        self._record_message("OUTGOING_BROADCAST", self.peer_id, "*", message_text, "Signed Broadcast",
                             receipt=receipt_info, message_hash=msg_hash)
        self._log_event(f"📤 Broadcasted signed message: \"{message_text}\"")
        return {"success": True, "payload": payload, "receipt": receipt_info}

    async def join_channel(self, channel: str):
        """Join or create a custom group channel."""
        if not channel.startswith("#"):
            channel = "#" + channel
        self.joined_channels.add(channel)
        if channel not in self.channel_keys:
            self.channel_keys[channel] = self.get_channel_key(channel)
        self.active_channel = channel
        await self._send_routed("/channel/join/1.0.0", "*", {
            "peerId": self.peer_id,
            "channel": channel,
            "action": "JOIN"
        })
        self._log_event(f"Joined group channel {channel}")

    async def leave_channel(self, channel: str):
        """Leave a group channel."""
        if not channel.startswith("#"):
            channel = "#" + channel
        self.joined_channels.discard(channel)
        self.channel_members.pop(channel, None)
        self.channel_keys.pop(channel, None)
        await self._send_routed("/channel/join/1.0.0", "*", {
            "peerId": self.peer_id,
            "channel": channel,
            "action": "LEAVE"
        })
        if self.active_channel == channel:
            self.active_channel = next(iter(sorted(self.joined_channels)), "")
        self._log_event(f"Left channel {channel}")

    # ─────────────────────────────────────────────────────────────
    # DPKI Blockchain Lifecycle Operations
    # ─────────────────────────────────────────────────────────────

    async def _send_scoped_transaction(self, tx: Transaction) -> int:
        """
        Interaction-Graph Scoped Push: Deliver transaction only to active
        contacts (channel members, recent DMs), avoiding network-wide broadcast storms.
        """
        contacts = self.get_active_contacts() & self.connected_peers
        tx_dict = tx.to_dict()
        sent = 0
        for contact_id in contacts:
            if await self._send_routed("/chain/tx/1.0.0", contact_id, tx_dict):
                sent += 1
        self.metrics["packets_sent_scoped"] += sent
        return sent

    async def revoke_key(self, reason: int = RevocationReason.KEY_COMPROMISE) -> Dict[str, Any]:
        """Revoke active identity on-chain and gossip via scoped delivery."""
        res = await self.blockchain.revoke_key(self.peer_id, reason, self.private_key)
        if res.get("success"):
            self.revoked_peers.add(self.peer_id)
            self.revocation_cache[self.peer_id] = {
                "is_revoked": True,
                "status": "REVOKED",
                "cached_at": time.time(),
                "ttl": 300.0
            }
            count = await self._send_scoped_transaction(res["transaction"])
            self._log_event(f"🛑 Key REVOKED on blockchain! Scoped alert sent to {count} active contact(s).")
        return res

    async def unrevoke_key(self) -> Dict[str, Any]:
        """Reinstate key on-chain and gossip via scoped delivery."""
        res = await self.blockchain.unrevoke_key(self.peer_id, self.private_key)
        if res.get("success"):
            self.revoked_peers.discard(self.peer_id)
            self.revocation_cache[self.peer_id] = {
                "is_revoked": False,
                "status": "ACTIVE",
                "cached_at": time.time(),
                "ttl": 300.0
            }
            count = await self._send_scoped_transaction(res["transaction"])
            self._log_event(f"♻️  Key REINSTATED on blockchain! Scoped update sent to {count} contact(s).")
        return res

    async def rotate_key(self) -> Dict[str, Any]:
        """Generate new keypair and record rotation on-chain via scoped delivery."""
        if self.peer_id in self.revoked_peers:
            return {"success": False, "error": "Cannot rotate revoked identity"}

        new_kp = self.crypto_suite.generate_keypair()
        new_did = create_did(self.peer_id, new_kp["publicKey"])

        res = await self.blockchain.rotate_key(
            self.peer_id, new_kp["publicKey"], new_did["id"], self.private_key
        )
        if res.get("success"):
            self.private_key = new_kp["privateKey"]
            self.public_key = new_kp["publicKey"]
            self.did = new_did
            if self.identity_file:
                self._save_identity()
            count = await self._send_scoped_transaction(res["transaction"])
            self._log_event(f"✅ Key rotated on blockchain! Scoped update sent to {count} contact(s).")
        return res

    def _save_identity(self):
        if not self.identity_file:
            return
        try:
            with open(self.identity_file, "w", encoding="utf-8") as f:
                json.dump({
                    "peerId": self.peer_id,
                    "privateKey": self.private_key,
                    "publicKey": self.public_key,
                    "did": self.did
                }, f, indent=2)
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────
    # Auditing & State Queries
    # ─────────────────────────────────────────────────────────────

    async def lookup_peer(self, peer_id: str) -> Optional[Dict[str, Any]]:
        full_id = next((p for p in self.blockchain.state.keys() if p.startswith(peer_id)), peer_id)
        return await self.blockchain.resolve_key(full_id)

    def get_trust_matrix(self) -> List[Dict[str, Any]]:
        matrix = []
        for pid in list(self.connected_peers):
            score = self.trust_scores.get(pid, 50)
            is_rev = pid in self.revoked_peers
            on_chain = self.blockchain.state.get(pid)
            if on_chain and on_chain.get("isRevoked"):
                is_rev = True

            matrix.append({
                "peerId": pid,
                "score": score,
                "isRevoked": is_rev,
                "status": "REVOKED" if is_rev else ("ON_CHAIN_VERIFIED" if on_chain else "UNREGISTERED"),
                "publicKey": self.key_registry.get(pid, "Unknown")
            })
        return matrix

    def get_blockchain_history(self) -> List[Dict[str, Any]]:
        return [b.to_dict() for b in self.blockchain.chain]

    # ─────────────────────────────────────────────────────────────
    # Internal Network & Protocol Streaming Handlers
    # ─────────────────────────────────────────────────────────────

    def _make_envelope(self, protocol: str, target: str, data: dict) -> bytes:
        """Serialise a protocol message to a newline-delimited JSON frame."""
        envelope = {
            "type": "ROUTED_MSG",
            "protocol": protocol,
            "sender": self.peer_id,
            "target": target,
            "data": data,
        }
        return (json.dumps(envelope) + "\n").encode("utf-8")

    async def _write_to_peer(self, writer: asyncio.StreamWriter, raw: bytes) -> bool:
        try:
            if writer.is_closing() or len(raw) > MAX_FRAME_BYTES:
                return False
            writer.write(raw)
            await asyncio.wait_for(writer.drain(), timeout=3.0)
            return True
        except (ConnectionError, OSError, asyncio.TimeoutError):
            return False

    async def _send_routed(self, protocol: str, target: str, data: dict) -> bool:
        """Send directly to the recipient(s). The bootstrap never carries data."""
        raw = self._make_envelope(protocol, target, data)
        recipients = list(self._peer_writers.items()) if target == "*" else [
            (target, self._peer_writers.get(target))
        ]
        sent = False
        for pid, writer in recipients:
            if writer is None:
                continue
            if await self._write_to_peer(writer, raw):
                sent = True
            else:
                self._drop_peer_connection(pid, writer)
        return sent

    def _start_background_task(self, coroutine):
        task = asyncio.create_task(coroutine)
        self._background_tasks.add(task)

        def done(completed):
            self._background_tasks.discard(completed)
            if not completed.cancelled() and completed.exception():
                self._log_event(f"Network task failed: {completed.exception()}")

        task.add_done_callback(done)
        return task

    def _remember_peer_address(self, pid, host, port) -> bool:
        if (not isinstance(pid, str) or not pid or len(pid) > 256 or pid == self.peer_id
                or not isinstance(host, str) or not host or len(host) > 255
                or host in ("0.0.0.0", "::") or type(port) is not int
                or not 1 <= port <= 65535):
            return False
        address = (host, port)
        if self._peer_addresses.get(pid) != address:
            self._retry_at.pop(pid, None)
            self._retry_delay.pop(pid, None)
        self._peer_addresses[pid] = address
        return True

    def _discover_peer(self, entry):
        if not isinstance(entry, dict):
            return
        pid, host, port = entry.get("peerId"), entry.get("listenHost"), entry.get("listenPort")
        if self._remember_peer_address(pid, host, port) and pid not in self.connected_peers:
            self._start_background_task(self._connect_to_peer(pid, host, port))

    def _adopt_peer_connection(self, pid, writer, connection_id) -> bool:
        old = self._peer_writers.get(pid)
        # Both ends choose the same connection when they dial simultaneously.
        if old and not old.is_closing():
            if self._peer_connection_ids[pid] <= connection_id:
                return False
        first_connection = pid not in self.connected_peers
        self._peer_writers[pid] = writer
        self._peer_connection_ids[pid] = connection_id
        self.connected_peers.add(pid)
        self.revocation_cache.pop(pid, None)
        self._retry_at.pop(pid, None)
        self._retry_delay.pop(pid, None)
        if old and old is not writer:
            old.close()
        if first_connection:
            self._log_event(f"Direct P2P connection established with {pid[:16]}...")
            if self.on_peer_event:
                self.on_peer_event("PEER_JOINED", pid)
            if self.on_peer_update:
                self.on_peer_update()
        return True

    def _drop_peer_connection(self, pid, writer):
        writer.close()
        # A reader for an old connection must never remove its replacement.
        if self._peer_writers.get(pid) is not writer:
            return
        self._peer_writers.pop(pid, None)
        self._peer_connection_ids.pop(pid, None)
        self.connected_peers.discard(pid)
        self.revocation_cache.pop(pid, None)
        for members in self.channel_members.values():
            members.discard(pid)
        pending = self._pending_chain_syncs.get(pid)
        if pending and not pending[1].done():
            pending[1].set_result(False)
        self._retry_at[pid] = time.monotonic() + 0.2
        self._log_event(f"Direct P2P connection closed with {pid[:16]}...")
        if self.on_peer_event:
            self.on_peer_event("PEER_LEFT", pid)
        if self.on_peer_update:
            self.on_peer_update()

    async def _handle_inbound_peer(self, reader, writer):
        task = asyncio.current_task()
        self._background_tasks.add(task)
        pid = None
        try:
            hello = json.loads(await asyncio.wait_for(reader.readline(), timeout=4.0))
            pid = hello.get("peerId")
            token = hello.get("connectionId")
            if (hello.get("type") != "P2P_HELLO" or not isinstance(token, str)
                    or not token or len(token) > 128
                    or not self._remember_peer_address(
                        pid, hello.get("listenHost"), hello.get("listenPort"))):
                return
            accepted = self._adopt_peer_connection(pid, writer, (pid, token))
            reply = {"type": "P2P_HELLO_ACK", "connectionId": token,
                     "accepted": accepted, **self._listen_address(writer)}
            if not await self._write_to_peer(writer, (json.dumps(reply) + "\n").encode()):
                return
            if accepted:
                self._start_background_task(self._on_peer_join(pid, writer))
                await self._read_direct_peer(pid, reader, writer)
        except (ValueError, AttributeError, ConnectionError, OSError, asyncio.TimeoutError):
            pass
        finally:
            if isinstance(pid, str) and pid:
                self._drop_peer_connection(pid, writer)
            else:
                writer.close()
            self._background_tasks.discard(task)

    async def _connect_to_peer(self, pid: Optional[str], host: str, port: int) -> bool:
        if pid == self.peer_id or not self._is_running:
            return False
        key = pid or (host, port)
        lock = self._dial_locks.setdefault(key, asyncio.Lock())
        if lock.locked():
            return pid in self.connected_peers
        async with lock:
            if pid in self.connected_peers:
                return True
            writer = None
            adopted = False
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, limit=MAX_FRAME_BYTES), timeout=4.0
                )
                token = uuid.uuid4().hex
                hello = {"type": "P2P_HELLO", "connectionId": token,
                         **self._listen_address(writer)}
                if not await self._write_to_peer(writer, (json.dumps(hello) + "\n").encode()):
                    return False
                reply = json.loads(await asyncio.wait_for(reader.readline(), timeout=4.0))
                remote_id = reply.get("peerId")
                if (reply.get("type") != "P2P_HELLO_ACK" or reply.get("connectionId") != token
                        or (pid is not None and remote_id != pid)
                        or not self._remember_peer_address(
                            remote_id, reply.get("listenHost"), reply.get("listenPort"))):
                    return False
                if not reply.get("accepted"):
                    return remote_id in self.connected_peers
                pid = remote_id
                adopted = self._adopt_peer_connection(pid, writer, (self.peer_id, token))
                if adopted:
                    self._start_background_task(self._read_direct_peer(pid, reader, writer))
                    self._start_background_task(self._on_peer_join(pid, writer))
                return pid in self.connected_peers
            except (ValueError, AttributeError, ConnectionError, OSError, asyncio.TimeoutError):
                return False
            finally:
                if writer and not adopted:
                    writer.close()
                if not adopted:
                    delay = min(self._retry_delay.get(key, 0.5) * 2, 30.0)
                    self._retry_delay[key] = delay
                    self._retry_at[key] = time.monotonic() + delay

    async def _read_direct_peer(self, pid, reader, writer):
        try:
            while self._is_running and self._peer_writers.get(pid) is writer:
                line = await asyncio.wait_for(reader.readline(), timeout=self.peer_timeout)
                if not line:
                    break
                try:
                    msg = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if not isinstance(msg, dict):
                    continue
                if msg.get("type") == "P2P_PING":
                    if not await self._write_to_peer(writer, b'{"type":"P2P_PONG"}\n'):
                        break
                    continue
                if msg.get("type") == "P2P_PONG":
                    continue
                if (msg.get("type") != "ROUTED_MSG" or msg.get("sender") != pid
                        or msg.get("target") not in (self.peer_id, "*")):
                    continue
                # Existing payload signatures and key lifecycle checks still
                # apply. Bind the envelope sender to this connection's peer ID.
                if str(msg.get("protocol", "")).startswith("/chat/"):
                    self._start_background_task(self._handle_protocol_message(msg))
                else:
                    await self._handle_protocol_message(msg)
        except (ValueError, ConnectionError, OSError, asyncio.TimeoutError):
            pass
        finally:
            self._drop_peer_connection(pid, writer)

    async def _maintain_peer_connections(self):
        last_ping = time.monotonic()
        while self._is_running:
            for pid, (host, port) in list(self._peer_addresses.items()):
                if pid not in self.connected_peers and time.monotonic() >= self._retry_at.get(pid, 0):
                    self._start_background_task(self._connect_to_peer(pid, host, port))
            live_addresses = {self._peer_addresses.get(pid) for pid in self.connected_peers}
            for host, port in self.seed_peers:
                if (host, port) not in live_addresses and time.monotonic() >= self._retry_at.get((host, port), 0):
                    self._start_background_task(self._connect_to_peer(None, host, port))
            if time.monotonic() - last_ping >= self.heartbeat_interval:
                for pid, writer in list(self._peer_writers.items()):
                    if not await self._write_to_peer(writer, b'{"type":"P2P_PING"}\n'):
                        self._drop_peer_connection(pid, writer)
                last_ping = time.monotonic()
            await asyncio.sleep(0.5)

    async def _handle_protocol_message(self, msg: dict):
        try:
            await self._dispatch_protocol(msg)
        except Exception as exc:
            self._log_event(f"Rejected malformed protocol message: {exc}")

    async def _broadcast_transaction(self, tx: Transaction):
        await self._send_routed("/chain/tx/1.0.0", "*", tx.to_dict())

    async def _bootstrap_loop(self):
        """Refresh discovery independently of all established peer connections."""
        unavailable_logged = False
        while self._is_running:
            writer = None
            registered = False
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.relay_host, self.relay_port, limit=MAX_FRAME_BYTES),
                    timeout=3.0,
                )
                self._relay_reader, self._relay_writer = reader, writer
                registration = {"type": "REGISTER_PEER", **self._listen_address(writer)}
                writer.write((json.dumps(registration) + "\n").encode())
                await asyncio.wait_for(writer.drain(), timeout=3.0)
                registered = True
                unavailable_logged = False
                self._log_event(f"Discovery connected at {self.relay_host}:{self.relay_port}")
                if self.on_peer_event:
                    self.on_peer_event("RELAY_CONNECTED", "")
                await self._relay_listener(reader)
            except (ValueError, ConnectionError, OSError, asyncio.TimeoutError):
                if not unavailable_logged:
                    self._log_event("Bootstrap unavailable; direct peer connections remain independent.")
                    unavailable_logged = True
            finally:
                if self._relay_writer is writer:
                    self._relay_reader = None
                    self._relay_writer = None
                if writer:
                    writer.close()
                if registered and self._is_running:
                    self._log_event("Discovery disconnected; direct peer connections are unchanged.")
                    if self.on_peer_event:
                        self.on_peer_event("RELAY_DISCONNECTED", "")
            await asyncio.sleep(2.0)

    async def _relay_listener(self, reader):
        while self._is_running:
            line = await reader.readline()
            if not line:
                return
            try:
                msg = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(msg, dict):
                continue
            if msg.get("type") == "PEER_LIST":
                for entry in msg.get("peers", []):
                    self._discover_peer(entry)
            elif msg.get("type") == "PEER_JOINED":
                self._discover_peer(msg)
            # PEER_LEFT means "left the directory", not "direct link lost".
            # Application messages from the directory are never dispatched.

    async def _on_peer_join(self, pid: str, writer=None):
        if writer is not None and self._peer_writers.get(pid) is not writer:
            return
        tx = self._registration_tx
        if tx is None:
            tx = Transaction(type=TransactionType.REGISTER_KEY, senderPeerId=self.peer_id,
                             payload={"publicKeyHex": self.public_key, "didUri": self.did["id"]})
            tx.sign(self.private_key)
            self._registration_tx = tx
        await self._send_routed("/did/1.0.0", pid, {
            **self._listen_address(writer), "did": self.did,
            "publicKey": self.public_key, "regTx": tx.to_dict(),
        })
        await self._send_routed("/chain/sync/1.0.0", pid, {"type": "GET_CHAIN"})
        for ch in sorted(self.joined_channels):
            await self._send_routed("/channel/join/1.0.0", pid,
                                    {"peerId": self.peer_id, "channel": ch, "action": "STATE"})
        await self._send_routed("/p2p/pex/1.0.0", pid, {"action": "REQUEST"})


    async def _dispatch_protocol(self, msg: dict):
        proto = msg.get("protocol")
        sender = msg.get("sender")
        data = msg.get("data", {})

        if sender == self.peer_id:
            return

        if proto == "/did/1.0.0":
            pid = data.get("peerId")
            if pid != sender:
                return
            pk = data.get("publicKey")
            reg_tx = data.get("regTx")
            if pid and pk and pid == sender and reg_tx:
                tx = Transaction.from_dict(reg_tx)
                if tx.senderPeerId != pid or tx.type != TransactionType.REGISTER_KEY:
                    return
                self.blockchain.add_transaction(tx)
                self._refresh_peer_state(pid)

            self._discover_peer(data)

        elif proto == "/p2p/pex/1.0.0":
            # Peer Exchange: share known peer addresses with newcomers
            action = data.get("action")
            if action == "REQUEST":
                # Send our known peer address table
                peers_info = {
                    pid: {"host": addr[0], "port": addr[1]}
                    for pid, addr in self._peer_addresses.items()
                    if pid != sender and pid in self.connected_peers
                }
                # Also include ourselves
                peers_info[self.peer_id] = {
                    "host": getattr(self, "_advertise_host", "127.0.0.1"),
                    "port": self.listen_port,
                }
                await self._send_routed("/p2p/pex/1.0.0", sender, {
                    "action": "RESPONSE", "peers": peers_info
                })
            elif action == "RESPONSE":
                peers_info = data.get("peers", {})
                for pid, addr in peers_info.items():
                    if isinstance(addr, dict):
                        self._discover_peer({
                            "peerId": pid, "listenHost": addr.get("host"),
                            "listenPort": addr.get("port"),
                        })

        elif proto == "/chat/dm/1.0.0":
            if data.get("to") != self.peer_id:
                return

            # Self-check: If OUR key is revoked, reject incoming DMs
            # (a revoked node must not accept messages on a compromised identity)
            if self.peer_id in self.revoked_peers:
                self._log_event(f"🚫 Rejected incoming DM — our own key is REVOKED. Cannot accept messages.")
                return

            from_peer = data.get("from", sender)
            enc_data = data.get("encryptedData")
            if from_peer != sender or not isinstance(enc_data, dict):
                return

            # Check revocation with Lazy On-Demand verification
            lazy_check = await self.verify_peer_revocation_lazy(from_peer, force_refresh=from_peer in self.revoked_peers)
            if self.peer_id in self.revoked_peers or lazy_check.get("is_revoked") or not lazy_check.get("verified"):
                self.trust_scores[from_peer] = 0
                self._log_event(f"🚫 Quarantined DM from REVOKED peer {from_peer[:16]}...")
                return

            sender_key = self.key_registry.get(from_peer)
            if not sender_key:
                return

            # Verify signature
            sig_payload = f"{enc_data['ciphertext']}:{enc_data['iv']}:{enc_data['tag']}:{data.get('timestamp')}"
            if not self.crypto_suite.verify(sig_payload, data.get("signature"), sender_key):
                self.trust_scores[from_peer] = max(0, self.trust_scores.get(from_peer, 50) - 25)
                self._log_event(f"❌ Bad signature on DM from {from_peer[:16]}...")
                return

            try:
                decrypted = self.crypto_suite.decrypt_dm(enc_data, sender_key, self.private_key)
                cur = self.trust_scores.get(from_peer, 50)
                self.trust_scores[from_peer] = min(100, cur + 5)
                receipt_info = data.get("receipt")
                computed_hash = self.crypto_suite.hash(sig_payload)
                self._record_message(
                    "INCOMING_DM", from_peer, self.peer_id, decrypted, "1-on-1 E2EE",
                    receipt=receipt_info, message_hash=computed_hash
                )
                if self.on_message_received:
                    self.on_message_received(self.message_history[-1])
            except Exception as e:
                self._log_event(f"Decryption failed for DM from {from_peer[:16]}...: {e}")

        elif proto == "/chat/channel/1.0.0":
            channel = data.get("channel")
            if channel not in self.joined_channels:
                return

            # Self-check: If OUR key is revoked, reject incoming channel messages
            if self.peer_id in self.revoked_peers:
                self._log_event(f"🚫 Rejected channel message — our own key is REVOKED.")
                return

            from_peer = data.get("from", sender)
            enc_data = data.get("encryptedData")
            if from_peer != sender or not isinstance(enc_data, dict):
                return

            # Check revocation with Lazy On-Demand verification
            lazy_check = await self.verify_peer_revocation_lazy(from_peer, force_refresh=from_peer in self.revoked_peers)
            if self.peer_id in self.revoked_peers or lazy_check.get("is_revoked") or not lazy_check.get("verified"):
                self.trust_scores[from_peer] = 0
                self._log_event(f"🚫 Quarantined channel message from REVOKED peer {from_peer[:16]}...")
                return

            sender_key = self.key_registry.get(from_peer)
            if not sender_key:
                on_chain = await self.blockchain.resolve_key(from_peer)
                if on_chain and on_chain.get("publicKeyHex"):
                    sender_key = on_chain["publicKeyHex"]
                    self.key_registry[from_peer] = sender_key

            sig_payload = f"{channel}:{enc_data.get('ciphertext')}:{enc_data.get('iv')}:{enc_data.get('tag')}:{data.get('timestamp')}"
            if not sender_key or not self.crypto_suite.verify(sig_payload, data.get("signature"), sender_key):
                self.trust_scores[from_peer] = max(0, self.trust_scores.get(from_peer, 50) - 25)
                self._log_event(f"❌ Bad signature on channel message from {from_peer[:16]}...")
                return

            channel_key = self.channel_keys.get(channel) or self.get_channel_key(channel)
            self.channel_keys[channel] = channel_key

            try:
                decrypted = self.crypto_suite.decrypt_channel(enc_data, channel_key)
                receipt_info = data.get("receipt")
                computed_hash = self.crypto_suite.hash(sig_payload)
                self._record_message("INCOMING_CHANNEL", from_peer, channel, decrypted, f"Channel {channel}",
                                     receipt=receipt_info, message_hash=computed_hash)
                if self.on_message_received:
                    self.on_message_received(self.message_history[-1])
            except Exception as e:
                self._log_event(f"Channel decryption failed: {e}")

        elif proto == "/chain/tx/1.0.0":
            try:
                tx = Transaction.from_dict(data)
                result = self.blockchain.add_transaction(tx)
                if not result.get("success"):
                    self._log_event(f"Rejected invalid blockchain transaction: {result.get('error')}")
                    return
                if tx.type == TransactionType.REVOKE_KEY and not result.get("duplicate"):
                    self.metrics["packets_received_revocation"] += 1
                self._refresh_peer_state(tx.senderPeerId)
            except Exception as exc:
                self._log_event(f"Rejected malformed blockchain transaction: {exc}")

        elif proto == "/chain/sync/1.0.0":
            if data.get("type") == "GET_CHAIN":
                resp = {"type": "CHAIN_RESPONSE", "chain": self.get_blockchain_history(),
                        "requestId": data.get("requestId")}
                await self._send_routed("/chain/sync/1.0.0", sender, resp)
            elif data.get("type") == "CHAIN_RESPONSE":
                chain_data = data.get("chain", [])
                valid = self.blockchain.is_valid_chain(chain_data)
                pending = self._pending_chain_syncs.get(sender)
                matches_request = pending and data.get("requestId") == pending[0]
                if not valid:
                    if matches_request and not pending[1].done():
                        pending[1].set_result(False)
                    self._log_event("Rejected invalid chain response.")
                    return
                old_len = len(self.blockchain.chain)
                if len(chain_data) > len(self.blockchain.chain):
                    if self.blockchain.replace_chain(chain_data):
                        self._resync_state_from_chain()
                        new_len = len(self.blockchain.chain)
                        log_msg = f"⛓️  [BLOCKCHAIN CONSENSUS] Synced {new_len} blocks from peer (was {old_len})."
                        self._log_event(log_msg)
                        if self.on_blockchain_event:
                            self.on_blockchain_event("onChainSynced", {"oldHeight": old_len, "newHeight": new_len})
                if matches_request:
                    # A shorter fork can still contain newer signed lifecycle
                    # transactions for the queried peer. Import those after
                    # validating the remote chain instead of caching stale state.
                    known_hashes = {tx.calculate_hash() for block in self.blockchain.chain for tx in block.transactions}
                    local_record = self.blockchain.state.get(sender, {})
                    for block in chain_data[1:]:
                        for tx_data in block.get("transactions", []):
                            tx = Transaction.from_dict(tx_data)
                            if (tx.senderPeerId == sender and tx.calculate_hash() not in known_hashes
                                    and tx.timestamp >= local_record.get("updatedAt", 0)):
                                result = self.blockchain.add_transaction(tx)
                                if result.get("success"):
                                    known_hashes.add(tx.calculate_hash())
                                    local_record = self.blockchain.state.get(sender, {})
                    self._resync_state_from_chain()
                    remote_ledger = NativeBlockchain(difficulty=self.blockchain.difficulty)
                    for block in chain_data[1:]:
                        for tx_data in block.get("transactions", []):
                            remote_ledger.apply_transaction_to_state(Transaction.from_dict(tx_data))
                    remote_record = remote_ledger.state.get(sender)
                    current_record = self.blockchain.state.get(sender)
                    verified = bool(remote_record and current_record
                                    and remote_record.get("publicKeyHex") == current_record.get("publicKeyHex")
                                    and bool(remote_record.get("isRevoked")) == bool(current_record.get("isRevoked")))
                    if not pending[1].done():
                        pending[1].set_result(verified)

        elif proto == "/chat/1.0.0":
            if self.peer_id in self.revoked_peers:
                return
            from_peer = data.get("from", sender)
            if from_peer != sender:
                return
            msg_text = data.get("message", "")
            sig = data.get("signature")
            lazy_check = await self.verify_peer_revocation_lazy(from_peer, force_refresh=from_peer in self.revoked_peers)
            if self.peer_id in self.revoked_peers or lazy_check.get("is_revoked") or not lazy_check.get("verified"):
                self._log_event(f"🚫 Quarantined broadcast from REVOKED peer {from_peer[:16]}...")
                return
            sender_key = self.key_registry.get(from_peer)
            if not sender_key or not sig or not self.crypto_suite.verify(msg_text, sig, sender_key):
                self._log_event(f"❌ Bad signature on broadcast from {from_peer[:16]}...")
                return
            receipt_info = data.get("receipt")
            computed_hash = self.crypto_suite.hash(f"{msg_text}:{sig}")
            self._record_message("INCOMING_BROADCAST", from_peer, "*", msg_text, "Signed Broadcast",
                                 receipt=receipt_info, message_hash=computed_hash)
            if self.on_message_received:
                self.on_message_received(self.message_history[-1])

        elif proto == "/channel/join/1.0.0":
            pid = data.get("peerId", sender)
            ch = data.get("channel")
            action = data.get("action")
            if ch and pid == sender and ch in self.joined_channels:
                members = self.channel_members.setdefault(ch, set())
                if action in ("JOIN", "STATE"):
                    members.add(pid)
                    self._log_event(f"Peer {pid[:16]}... joined {ch}")
                    if action == "JOIN":
                        await self._send_routed("/channel/join/1.0.0", pid,
                                                {"peerId": self.peer_id, "channel": ch, "action": "STATE"})
                elif action == "LEAVE":
                    members.discard(pid)
                    self._log_event(f"Peer {pid[:16]}... left {ch}")
                if self.on_peer_update:
                    self.on_peer_update()

    def _record_message(self, kind: str, sender: str, target: str, text: str, mode: str,
                        receipt: Optional[Dict[str, Any]] = None, message_hash: Optional[str] = None):
        record = {
            "kind": kind,
            "sender": sender,
            "target": target,
            "text": text,
            "mode": mode,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "receipt": receipt,
            "messageHash": message_hash
        }
        self.message_history.append(record)
        if len(self.message_history) > 100:
            self.message_history.pop(0)
