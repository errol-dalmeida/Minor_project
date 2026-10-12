import asyncio
from datetime import datetime
import json
import os
import random
import string
import sys
import time
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


class PeerNode:
    """
    Decentralized Sovereign Peer Node Engine.
    Exposes modular, code-first Python functions for all P2P operations.
    """
    def __init__(
        self,
        peer_id: Optional[str] = None,
        relay_host: str = "127.0.0.1",
        relay_port: int = 4001,
        crypto_suite: Optional[CryptoSuite] = None,
        auto_register_blockchain: bool = True,
        identity_file: Optional[str] = None
    ):
        self.relay_host = relay_host
        self.relay_port = relay_port
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
        self.channel_keys: Dict[str, str] = {"#general": self.crypto_suite.hash("public-general-channel-salt")}
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

        self._relay_reader: Optional[asyncio.StreamReader] = None
        self._relay_writer: Optional[asyncio.StreamWriter] = None
        self._listener_task: Optional[asyncio.Task] = None
        self._is_running = False
        self.auto_register_blockchain = auto_register_blockchain

        self._setup_blockchain_listeners()

    def _setup_blockchain_listeners(self):
        def on_revoked(data):
            pid = str(data.get("peerId"))
            self.revoked_peers.add(pid)
            self.trust_scores[pid] = 0
            log_msg = f"🚨 [BLOCKCHAIN] Peer {pid[:16]}... REVOKED on-chain! Reason: {data.get('reason')}"
            self._log_event(log_msg)
            if self.on_blockchain_event:
                self.on_blockchain_event("onKeyRevoked", data)

        def on_unrevoked(data):
            pid = str(data.get("peerId"))
            self.revoked_peers.discard(pid)
            self.trust_scores[pid] = 50
            log_msg = f"♻️  [BLOCKCHAIN] Peer {pid[:16]}... REINSTATED on-chain!"
            self._log_event(log_msg)
            if self.on_blockchain_event:
                self.on_blockchain_event("onKeyUnrevoked", data)

        def on_rotated(data):
            pid = str(data.get("peerId"))
            self.key_registry[pid] = data.get("newKey")
            self.revoked_peers.discard(pid)
            log_msg = f"🔄 [BLOCKCHAIN] Peer {pid[:16]}... rotated public key!"
            self._log_event(log_msg)
            if self.on_blockchain_event:
                self.on_blockchain_event("onKeyRotated", data)

        def on_registered(data):
            pid = str(data.get("peerId"))
            self.key_registry[pid] = data.get("publicKeyHex")
            if pid not in self.trust_scores:
                self.trust_scores[pid] = 50
            log_msg = f"🆔 [BLOCKCHAIN] Peer {pid[:16]}... registered key on-chain."
            self._log_event(log_msg)
            if self.on_blockchain_event:
                self.on_blockchain_event("onKeyRegistered", data)

        self.blockchain.subscribe_events({
            "onKeyRevoked": on_revoked,
            "onKeyUnrevoked": on_unrevoked,
            "onKeyRotated": on_rotated,
            "onKeyRegistered": on_registered
        })

    def _log_event(self, text: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] {text}"
        self.event_log.append(entry)
        if len(self.event_log) > 200:
            self.event_log.pop(0)

    # ─────────────────────────────────────────────────────────────
    # Lifecycle Methods
    # ─────────────────────────────────────────────────────────────

    async def start(self) -> bool:
        """Initialize blockchain identity and connect to relay."""
        self._is_running = True

        if self.auto_register_blockchain:
            reg_res = await self.blockchain.register_key(
                self.peer_id, self.public_key, self.did["id"], self.private_key
            )
            if reg_res.get("success"):
                b = reg_res["block"]
                self._log_event(f"Identity registered on local chain in Block #{b.index}")

        try:
            reader, writer = await asyncio.open_connection(self.relay_host, self.relay_port)
            self._relay_reader = reader
            self._relay_writer = writer

            # Handshake
            handshake = {"type": "REGISTER_PEER", "peerId": self.peer_id}
            writer.write((json.dumps(handshake) + "\n").encode("utf-8"))
            await writer.drain()

            self._listener_task = asyncio.create_task(self._relay_listener(reader))
            self._log_event(f"Connected to P2P relay at {self.relay_host}:{self.relay_port}")
            return True
        except Exception as e:
            self._log_event(f"Relay connection unavailable: {e}. Running standalone.")
            return False

    async def stop(self):
        """Cleanly disconnect from relay."""
        self._is_running = False
        if self._listener_task:
            self._listener_task.cancel()
        if self._relay_writer:
            try:
                self._relay_writer.close()
                await self._relay_writer.wait_closed()
            except Exception:
                pass
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
            self.channel_keys[ch] = self.crypto_suite.hash(f"public-{ch}-channel-salt")
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
        for members in self.channel_members.values():
            contacts.update(members)
        for msg in self.message_history:
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

        On cache miss: queries local chain first, then triggers a chain sync
        request to the target peer to fetch the latest revocation state from
        the network (fixes the 'stranger gap' where scoped delivery skipped us).
        """
        now = time.time()
        cached = self.revocation_cache.get(peer_id)
        if not force_refresh and cached and (now - cached.get("cached_at", 0) < ttl):
            self.metrics["cache_hits"] += 1
            return {
                "is_revoked": cached["is_revoked"],
                "status": cached["status"],
                "from_cache": True
            }

        self.metrics["cache_misses"] += 1

        # Step 1: Request fresh chain data from the target peer.
        # This closes the 'stranger gap' — if we were outside the scoped
        # delivery radius, we pull the latest chain state on-demand.
        if self._relay_writer and peer_id in self.connected_peers:
            await self._send_routed("/chain/sync/1.0.0", peer_id, {"type": "GET_CHAIN"})
            # Brief wait for the CHAIN_RESPONSE to arrive and be processed
            await asyncio.sleep(0.5)
            self.metrics.setdefault("chain_syncs_on_demand", 0)
            self.metrics["chain_syncs_on_demand"] += 1

        # Step 2: Now check the (potentially updated) local chain
        on_chain = await self.blockchain.verify_key(peer_id, self.key_registry.get(peer_id, ""))
        is_rev = bool(on_chain.get("isRevoked") or peer_id in self.revoked_peers)
        status = on_chain.get("status", "REVOKED" if is_rev else "ACTIVE")

        if is_rev:
            self.revoked_peers.add(peer_id)
            self.trust_scores[peer_id] = 0

        self.revocation_cache[peer_id] = {
            "is_revoked": is_rev,
            "status": status,
            "cached_at": now,
            "ttl": ttl
        }
        return {
            "is_revoked": is_rev,
            "status": status,
            "from_cache": False
        }

    async def send_direct_message(self, recipient_id: str, message_text: str) -> Dict[str, Any]:
        """Send confidential 1-on-1 ECIES encrypted DM with on-demand lazy check."""
        if self.peer_id in self.revoked_peers:
            err = "Cannot send DM: Your local identity is REVOKED on-chain."
            self._log_event(f"🚫 {err}")
            return {"success": False, "error": err}

        # 1. On-Demand Lazy Revocation Check
        lazy_check = await self.verify_peer_revocation_lazy(recipient_id)
        if lazy_check.get("is_revoked"):
            err = f"Blocked DM: Recipient {recipient_id[:16]}... key is REVOKED on-chain."
            self._log_event(f"🚫 {err}")
            return {"success": False, "error": err}

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

        payload = {
            "from": self.peer_id,
            "to": recipient_id,
            "encryptedData": encrypted_data,
            "signature": signature,
            "timestamp": timestamp
        }

        await self._send_routed("/chat/dm/1.0.0", recipient_id, payload)
        self._record_message("OUTGOING_DM", self.peer_id, recipient_id, message_text, "1-on-1 E2EE")
        self._log_event(f"🔒 Sent ECIES DM to {recipient_id[:16]}...: \"{message_text}\"")
        return {"success": True, "payload": payload}

    async def send_channel_message(self, channel: str, message_text: str) -> Dict[str, Any]:
        """Send encrypted message to group channel."""
        if channel not in self.joined_channels:
            err = f"Must join {channel} before sending."
            self._log_event(f"❌ {err}")
            return {"success": False, "error": err}

        channel_key = self.channel_keys.get(channel)
        if not channel_key:
            channel_key = self.crypto_suite.hash(f"channel-key-salt-{channel}")
            self.channel_keys[channel] = channel_key

        encrypted_data = self.crypto_suite.encrypt_channel(message_text, channel_key)
        timestamp = int(time.time() * 1000)

        sig_payload = f"{channel}:{encrypted_data['ciphertext']}:{encrypted_data['iv']}:{encrypted_data['tag']}:{timestamp}"
        signature = self.crypto_suite.sign(sig_payload, self.private_key)

        payload = {
            "channel": channel,
            "from": self.peer_id,
            "encryptedData": encrypted_data,
            "signature": signature,
            "timestamp": timestamp
        }

        await self._send_routed("/chat/channel/1.0.0", "*", payload)
        self._record_message("OUTGOING_CHANNEL", self.peer_id, channel, message_text, f"Channel {channel}")
        self._log_event(f"📢 Sent encrypted message to {channel}: \"{message_text}\"")
        return {"success": True, "payload": payload}

    async def send_broadcast(self, message_text: str) -> Dict[str, Any]:
        """Send signed public broadcast message."""
        sig = self.crypto_suite.sign(message_text, self.private_key)
        payload = {"from": self.peer_id, "message": message_text, "signature": sig}
        await self._send_routed("/chat/1.0.0", "*", payload)
        self._record_message("OUTGOING_BROADCAST", self.peer_id, "*", message_text, "Signed Broadcast")
        self._log_event(f"📤 Broadcasted signed message: \"{message_text}\"")
        return {"success": True}

    async def join_channel(self, channel: str):
        """Join or create a custom group channel."""
        if not channel.startswith("#"):
            channel = "#" + channel
        self.joined_channels.add(channel)
        if channel not in self.channel_keys:
            self.channel_keys[channel] = self.crypto_suite.hash(f"channel-key-salt-{channel}")
        self.active_channel = channel
        await self._send_routed("/channel/join/1.0.0", "*", {
            "peerId": self.peer_id,
            "channel": channel,
            "action": "JOIN"
        })
        self._log_event(f"Joined group channel {channel}")

    async def leave_channel(self, channel: str):
        """Leave a group channel."""
        if channel == "#general":
            self._log_event("Cannot leave default #general channel.")
            return
        self.joined_channels.discard(channel)
        await self._send_routed("/channel/join/1.0.0", "*", {
            "peerId": self.peer_id,
            "channel": channel,
            "action": "LEAVE"
        })
        if self.active_channel == channel:
            self.active_channel = "#general"
        self._log_event(f"Left channel {channel}")

    # ─────────────────────────────────────────────────────────────
    # DPKI Blockchain Lifecycle Operations
    # ─────────────────────────────────────────────────────────────

    async def _send_scoped_transaction(self, tx: Transaction) -> int:
        """
        Interaction-Graph Scoped Push: Deliver transaction only to active
        contacts (channel members, recent DMs), avoiding network-wide broadcast storms.
        """
        contacts = self.get_active_contacts()
        tx_dict = tx.to_dict()
        for contact_id in contacts:
            await self._send_routed("/chain/tx/1.0.0", contact_id, tx_dict)
        self.metrics["packets_sent_scoped"] += len(contacts)
        return len(contacts)

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

    async def _send_routed(self, protocol: str, target: str, data: dict):
        if not self._relay_writer:
            return
        envelope = {
            "type": "ROUTED_MSG",
            "protocol": protocol,
            "sender": self.peer_id,
            "target": target,
            "data": data
        }
        try:
            line = json.dumps(envelope) + "\n"
            self._relay_writer.write(line.encode("utf-8"))
            await self._relay_writer.drain()
        except Exception:
            pass

    async def _broadcast_transaction(self, tx: Transaction):
        await self._send_routed("/chain/tx/1.0.0", "*", tx.to_dict())

    async def _relay_listener(self, reader: asyncio.StreamReader):
        while self._is_running:
            try:
                line = await reader.readline()
                if not line:
                    break
                msg = json.loads(line.decode("utf-8").strip())
            except Exception:
                continue

            mtype = msg.get("type")
            if mtype == "PEER_LIST":
                for pid in msg.get("peers", []):
                    if pid != self.peer_id and pid not in self.connected_peers:
                        self.connected_peers.add(pid)
                        asyncio.create_task(self._on_peer_join(pid))
                if self.on_peer_update:
                    self.on_peer_update()

            elif mtype == "PEER_JOINED":
                pid = msg.get("peerId")
                if pid and pid != self.peer_id:
                    self.connected_peers.add(pid)
                    asyncio.create_task(self._on_peer_join(pid))
                    if self.on_peer_update:
                        self.on_peer_update()

            elif mtype == "PEER_LEFT":
                pid = msg.get("peerId")
                self.connected_peers.discard(pid)
                for members in self.channel_members.values():
                    members.discard(pid)
                if self.on_peer_update:
                    self.on_peer_update()

            elif mtype == "ROUTED_MSG":
                await self._dispatch_protocol(msg)

    async def _on_peer_join(self, pid: str):
        await asyncio.sleep(0.3)
        # Announce DID & Initial Registration
        tx = Transaction(
            type=TransactionType.REGISTER_KEY,
            senderPeerId=self.peer_id,
            payload={"publicKeyHex": self.public_key, "didUri": self.did["id"]}
        )
        tx.sign(self.private_key)
        await self._send_routed("/did/1.0.0", pid, {
            "peerId": self.peer_id,
            "did": self.did,
            "publicKey": self.public_key,
            "regTx": tx.to_dict()
        })
        await asyncio.sleep(0.2)
        await self._send_routed("/chain/sync/1.0.0", pid, {"type": "GET_CHAIN"})

    async def _dispatch_protocol(self, msg: dict):
        proto = msg.get("protocol")
        sender = msg.get("sender")
        data = msg.get("data", {})

        if sender == self.peer_id:
            return

        if proto == "/did/1.0.0":
            pid = data.get("peerId")
            pk = data.get("publicKey")
            reg_tx = data.get("regTx")
            if pid and pk:
                self.key_registry[pid] = pk
                if reg_tx:
                    self.blockchain.add_transaction(Transaction.from_dict(reg_tx))
                elif pid not in self.blockchain.state:
                    self.blockchain.state[pid] = {
                        "peerId": pid,
                        "publicKeyHex": pk,
                        "didUri": data.get("did", {}).get("id", f"did:peer:{pid}"),
                        "isRevoked": False,
                        "reason": RevocationReason.NONE,
                        "createdAt": int(time.time() * 1000),
                        "updatedAt": int(time.time() * 1000),
                        "revokedAt": 0
                    }
                on_chain = await self.blockchain.resolve_key(pid)
                if on_chain and on_chain.get("isRevoked"):
                    self.revoked_peers.add(pid)
                    self.trust_scores[pid] = 0
                elif pid not in self.trust_scores:
                    self.trust_scores[pid] = 50

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

            # Check revocation with Lazy On-Demand verification
            lazy_check = await self.verify_peer_revocation_lazy(from_peer)
            if lazy_check.get("is_revoked"):
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
                self._record_message("INCOMING_DM", from_peer, self.peer_id, decrypted, "1-on-1 E2EE")
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

            # Check revocation with Lazy On-Demand verification
            lazy_check = await self.verify_peer_revocation_lazy(from_peer)
            if lazy_check.get("is_revoked"):
                self.trust_scores[from_peer] = 0
                self._log_event(f"🚫 Quarantined channel message from REVOKED peer {from_peer[:16]}...")
                return

            sender_key = self.key_registry.get(from_peer)
            if not sender_key:
                return

            channel_key = self.channel_keys.get(channel)
            if not channel_key:
                return

            try:
                decrypted = self.crypto_suite.decrypt_channel(enc_data, channel_key)
                self._record_message("INCOMING_CHANNEL", from_peer, channel, decrypted, f"Channel {channel}")
                if self.on_message_received:
                    self.on_message_received(self.message_history[-1])
            except Exception:
                pass

        elif proto == "/chain/tx/1.0.0":
            try:
                tx = Transaction.from_dict(data)
                self.blockchain.add_transaction(tx)
                if tx.type == TransactionType.REVOKE_KEY:
                    self.metrics["packets_received_revocation"] += 1
                    self.revoked_peers.add(tx.senderPeerId)
                    self.trust_scores[tx.senderPeerId] = 0
                    self.revocation_cache[tx.senderPeerId] = {
                        "is_revoked": True,
                        "status": "REVOKED",
                        "cached_at": time.time(),
                        "ttl": 300.0
                    }
                elif tx.type == TransactionType.UNREVOKE_KEY:
                    self.revoked_peers.discard(tx.senderPeerId)
                    self.trust_scores[tx.senderPeerId] = 50
                    self.revocation_cache[tx.senderPeerId] = {
                        "is_revoked": False,
                        "status": "ACTIVE",
                        "cached_at": time.time(),
                        "ttl": 300.0
                    }
            except Exception:
                pass

        elif proto == "/chain/sync/1.0.0":
            if data.get("type") == "GET_CHAIN":
                resp = {"type": "CHAIN_RESPONSE", "chain": [b.to_dict() for b in self.blockchain.chain]}
                await self._send_routed("/chain/sync/1.0.0", sender, resp)
            elif data.get("type") == "CHAIN_RESPONSE":
                chain_data = data.get("chain", [])
                if len(chain_data) > len(self.blockchain.chain):
                    self.blockchain.replace_chain(chain_data)

    def _record_message(self, kind: str, sender: str, target: str, text: str, mode: str):
        record = {
            "kind": kind,
            "sender": sender,
            "target": target,
            "text": text,
            "mode": mode,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }
        self.message_history.append(record)
        if len(self.message_history) > 100:
            self.message_history.pop(0)
