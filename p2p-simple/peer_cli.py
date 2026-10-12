#!/usr/bin/env python3
"""
P2P Sovereign Node CLI (Pure Terminal, Zero UI)
==============================================
Fully decentralized sovereign peer node terminal interface with:
- Native in-code blockchain updates displayed in real-time
- ECIES 1-on-1 confidential direct messaging (ECDH + HKDF + AES-GCM / ChaCha20)
- Symmetric AEAD group channel messaging with interaction-graph scoping
- On-chain DPKI key lifecycle (Registration, Scoped Revocation, Reinstatement, Rotation)
- On-demand lazy revocation verification with local TTL caching
- Modular hot-swappable cryptographic suite (Strategy Pattern)
- Dynamic trust matrix and peer presence tracking
- Full LAN multi-device support via relay
"""

import argparse
import asyncio
from datetime import datetime
import json
import os
import sys
import time
from typing import Optional, List, Dict, Any

# Ensure UTF-8 output on Windows
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
from blockchain import RevocationReason, TransactionType
from peer_node import PeerNode

# ── ANSI Color Codes ──────────────────────────────────────────────
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_BLUE = "\033[44m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"


def c(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}"


# ──────────────────────────────────────────────────────────────────
# CLI Application
# ──────────────────────────────────────────────────────────────────

class PeerNodeCLI:
    def __init__(
        self,
        relay_host: str = "127.0.0.1",
        relay_port: int = 4001,
        identity_file: Optional[str] = None,
        peer_id: Optional[str] = None,
        initial_channel: str = "#general"
    ):
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.identity_file = identity_file
        self.node = PeerNode(
            peer_id=peer_id,
            relay_host=relay_host,
            relay_port=relay_port,
            identity_file=identity_file
        )
        if initial_channel and initial_channel != "#general":
            if not initial_channel.startswith("#"):
                initial_channel = "#" + initial_channel
            self.node.joined_channels.add(initial_channel)
            self.node.channel_keys[initial_channel] = self.node.get_channel_key(initial_channel)
            self.node.channel_members[initial_channel] = set()
            self.node.active_channel = initial_channel

        self._running = False
        self._setup_event_handlers()

    def _setup_event_handlers(self):
        """Register callbacks so blockchain, message, and network events print live to terminal."""

        def handle_blockchain_event(ev_type: str, data: Dict[str, Any]):
            ts = datetime.now().strftime("%H:%M:%S")
            if ev_type == "onKeyRegistered":
                pid = str(data.get("peerId", ""))
                pk = str(data.get("publicKeyHex", ""))[:20]
                print(f"\n{c(f'[{ts}] ⛓️  [BLOCKCHAIN UPDATE]', Colors.CYAN + Colors.BOLD)} "
                      f"{c('🆔 NEW KEY REGISTERED', Colors.GREEN)} | Peer: {c(pid[:16] + '...', Colors.YELLOW)} | PubKey: {pk}...")
                self._print_prompt()

            elif ev_type == "onKeyRevoked":
                pid = str(data.get("peerId", ""))
                reason_code = data.get("reason", 1)
                reason_map = {1: "Key Compromise", 2: "Superseded", 3: "Decommissioned", 4: "Malicious Activity"}
                reason_desc = reason_map.get(reason_code, f"Code {reason_code}")
                print(f"\n{c(f'[{ts}] ⛓️  [BLOCKCHAIN UPDATE]', Colors.RED + Colors.BOLD)} "
                      f"{c('🚨 IDENTITY REVOKED ON-CHAIN', Colors.RED + Colors.BOLD)} | "
                      f"Peer: {c(pid[:16] + '...', Colors.YELLOW)} | Reason: {c(reason_desc, Colors.WHITE)} | Trust: 0")
                self._print_prompt()

            elif ev_type == "onKeyUnrevoked":
                pid = str(data.get("peerId", ""))
                print(f"\n{c(f'[{ts}] ⛓️  [BLOCKCHAIN UPDATE]', Colors.GREEN + Colors.BOLD)} "
                      f"{c('♻️  KEY REINSTATED ON-CHAIN', Colors.GREEN + Colors.BOLD)} | "
                      f"Peer: {c(pid[:16] + '...', Colors.YELLOW)} | Trust: 50")
                self._print_prompt()

            elif ev_type == "onKeyRotated":
                pid = str(data.get("peerId", ""))
                nk = str(data.get("newKey", ""))[:20]
                print(f"\n{c(f'[{ts}] ⛓️  [BLOCKCHAIN UPDATE]', Colors.MAGENTA + Colors.BOLD)} "
                      f"{c('🔄 KEY ROTATED ON-CHAIN', Colors.MAGENTA + Colors.BOLD)} | "
                      f"Peer: {c(pid[:16] + '...', Colors.YELLOW)} | New PubKey: {nk}...")
                self._print_prompt()

            elif ev_type == "onBlockAdded":
                idx = data.get("index")
                h = str(data.get("hash", ""))[:16]
                tx_len = len(data.get("transactions", []))
                print(f"\n{c(f'[{ts}] ⛓️  [BLOCKCHAIN UPDATE]', Colors.CYAN + Colors.BOLD)} "
                      f"{c(f'📦 BLOCK #{idx} MINED & COMMITTED', Colors.CYAN)} | Hash: {h}... | Transactions: {tx_len}")
                self._print_prompt()

            elif ev_type == "onChainSynced":
                old_h = data.get("oldHeight", 0)
                new_h = data.get("newHeight", 0)
                print(f"\n{c(f'[{ts}] ⛓️  [BLOCKCHAIN CONSENSUS]', Colors.YELLOW + Colors.BOLD)} "
                      f"{c(f'🌐 Adopted longer valid chain from network', Colors.YELLOW)} ({old_h} ➔ {new_h} blocks)")
                self._print_prompt()

        def handle_message_received(msg: Dict[str, Any]):
            ts = msg.get("timestamp", datetime.now().strftime("%H:%M:%S"))
            kind = msg.get("kind", "")
            sender = msg.get("sender", "")
            target = msg.get("target", "")
            text = msg.get("text", "")

            if kind == "INCOMING_DM":
                print(f"\n{c(f'[{ts}] 🔒 [INCOMING DM (ECIES)]', Colors.GREEN + Colors.BOLD)} "
                      f"From {c(sender[:16] + '...', Colors.YELLOW)}: {c(text, Colors.WHITE + Colors.BOLD)}")
            elif kind == "INCOMING_CHANNEL":
                print(f"\n{c(f'[{ts}] 📢 [CHANNEL {target}]', Colors.CYAN + Colors.BOLD)} "
                      f"{c(sender[:16] + '...', Colors.YELLOW)}: {c(text, Colors.WHITE)}")
            elif kind == "INCOMING_BROADCAST":
                print(f"\n{c(f'[{ts}] 📤 [PUBLIC BROADCAST]', Colors.BLUE + Colors.BOLD)} "
                      f"{c(sender[:16] + '...', Colors.YELLOW)}: {c(text, Colors.WHITE)}")
            self._print_prompt()

        def handle_peer_event(event_type: str, pid: str):
            ts = datetime.now().strftime("%H:%M:%S")
            if event_type == "PEER_JOINED":
                print(f"\n{c(f'[{ts}] 🔗 [NETWORK]', Colors.CYAN + Colors.BOLD)} "
                      f"{c('Peer Connected:', Colors.GREEN)} {c(pid[:16] + '...', Colors.YELLOW)}")
                self._print_prompt()
            elif event_type == "PEER_LEFT":
                print(f"\n{c(f'[{ts}] 🔌 [NETWORK]', Colors.YELLOW + Colors.BOLD)} "
                      f"{c('Peer Disconnected:', Colors.YELLOW)} {c(pid[:16] + '...', Colors.DIM)}")
                self._print_prompt()
            elif event_type == "RELAY_DISCONNECTED":
                print(f"\n{c(f'[{ts}] ⚠️ [NETWORK]', Colors.RED + Colors.BOLD)} "
                      f"{c('Disconnected from Relay! Reconnecting in background...', Colors.RED)}")
                self._print_prompt()
            elif event_type == "RELAY_CONNECTED":
                print(f"\n{c(f'[{ts}] 🔗 [NETWORK]', Colors.GREEN + Colors.BOLD)} "
                      f"{c('Reconnected to Relay successfully!', Colors.GREEN)}")
                self._print_prompt()

        self.node.on_blockchain_event = handle_blockchain_event
        self.node.on_message_received = handle_message_received
        self.node.on_peer_event = handle_peer_event
        self.node.on_verification_event = self.handle_verification_event

    def handle_verification_event(self, text: str):
        print(f"\n{c(text, Colors.YELLOW)}")
        self._print_prompt()

    def _print_prompt(self):
        ch = self.node.active_channel or "no channel"
        is_revoked = self.node.peer_id in self.node.revoked_peers
        status_tag = c("[REVOKED]", Colors.RED) if is_revoked else c("[ACTIVE]", Colors.GREEN)
        prompt_str = f"{status_tag} {c(f'({ch})', Colors.CYAN)} {c('>', Colors.WHITE + Colors.BOLD)} "
        sys.stdout.write(prompt_str)
        sys.stdout.flush()

    def print_banner(self):
        print(c("\n" + "=" * 70, Colors.CYAN))
        print(c("  🛡️  SOVEREIGN P2P COMMUNICATION NODE & DPKI BLOCKCHAIN (CLI)", Colors.CYAN + Colors.BOLD))
        print(c("=" * 70, Colors.CYAN))
        print(f"  • {c('Peer ID', Colors.BOLD):<18}: {c(self.node.peer_id, Colors.YELLOW)}")
        print(f"  • {c('DID URI', Colors.BOLD):<18}: {self.node.did['id']}")
        print(f"  • {c('Public Key', Colors.BOLD):<18}: {self.node.public_key[:32]}...")

        is_revoked = self.node.peer_id in self.node.revoked_peers
        if is_revoked:
            print(f"  • {c('Identity Status', Colors.BOLD):<18}: {c('🛑 REVOKED ON-CHAIN (QUARANTINED)', Colors.RED + Colors.BOLD)}")
        else:
            print(f"  • {c('Identity Status', Colors.BOLD):<18}: {c('✅ ACTIVE (REGISTERED ON-CHAIN)', Colors.GREEN + Colors.BOLD)}")

        print(f"  • {c('Crypto Suite', Colors.BOLD):<18}: {c(self.node.crypto_suite.get_descriptor(), Colors.MAGENTA)}")
        print(f"  • {c('Relay Server', Colors.BOLD):<18}: {self.relay_host}:{self.relay_port}")
        print(f"  • {c('Active Channel', Colors.BOLD):<18}: {c(self.node.active_channel, Colors.CYAN)}")
        print(f"  • {c('Joined Channels', Colors.BOLD):<18}: {', '.join(sorted(self.node.joined_channels))}")
        print(c("-" * 70, Colors.DIM))
        print(f"  Type {c('help', Colors.YELLOW)} for command list or {c('menu', Colors.GREEN + Colors.BOLD)} for guided interactive options.")
        print(c("=" * 70 + "\n", Colors.CYAN))

    def show_help(self):
        print(c("\n📜 Available CLI Commands:", Colors.CYAN + Colors.BOLD))
        commands = [
            ("@<peerId> <msg>", "Send confidential 1-on-1 E2EE direct message (ECIES)"),
            ("dm <peerId> <msg>", "Alternative syntax for ECIES direct message"),
            ("#<channel> <msg>", "Send encrypted message to specific channel (e.g. #dev hello)"),
            ("<message>", f"Send encrypted message to currently active channel ({self.node.active_channel})"),
            ("join <#channel>", "Join or create group channel (e.g. join #secops)"),
            ("leave <#channel>", "Leave group channel"),
            ("channel <#channel>", "Switch currently active channel"),
            ("channels", "List all joined channels and active channel"),
            ("broadcast <msg>", "Send signed public broadcast message to all peers"),
            ("revoke [1-4]", "Revoke identity on-chain with scoped gossip (1:Compromise, 2:Superseded, 3:Decom, 4:Malicious)"),
            ("unrevoke", "Reinstate / unrevoke key on-chain with scoped gossip"),
            ("rotate", "Generate new keypair and rotate on-chain with scoped gossip"),
            ("lookup <peerId>", "Query blockchain record & full key rotation history for a peer"),
            ("refresh <peerId>", "Pull current key status from a peer, bypassing the TTL cache"),
            ("chain / blocks", "Explore native blockchain height, difficulty, blocks, and transactions"),
            ("crypto", "Display active cryptographic suite descriptor"),
            ("crypto <hash> <cipher>", "Hot-swap crypto suite (e.g. 'crypto blake2b chacha20', 'crypto sha256 aes-gcm')"),
            ("peers", "List all connected peers in network"),
            ("trust", "Display peer trust matrix (scores 0-100 & verification badges)"),
            ("metrics", "Display scoped revocation gossip vs broadcast metrics & cache hits"),
            ("status", "Show comprehensive node and DPKI status dashboard"),
            ("menu", "Open full interactive numbered menu with step-by-step prompts"),
            ("clear", "Clear terminal screen"),
            ("exit / quit", "Safely disconnect and exit")
        ]
        for cmd, desc in commands:
            print(f"  {c(cmd, Colors.YELLOW):<26} {desc}")
        print()

    def show_status(self):
        print(c("\n📊 Sovereign Node Status Dashboard:", Colors.CYAN + Colors.BOLD))
        print(f"  • Peer ID        : {self.node.peer_id}")
        print(f"  • DID URI        : {self.node.did['id']}")
        print(f"  • Public Key     : {self.node.public_key}")

        is_revoked = self.node.peer_id in self.node.revoked_peers
        status_txt = c("🛑 REVOKED ON-CHAIN", Colors.RED + Colors.BOLD) if is_revoked else c("✅ ACTIVE (ON-CHAIN)", Colors.GREEN + Colors.BOLD)
        print(f"  • Status         : {status_txt}")
        print(f"  • Crypto Suite   : {self.node.crypto_suite.get_descriptor()}")
        print(f"  • Relay Endpoint : {self.relay_host}:{self.relay_port}")
        print(f"  • Active Channel : {self.node.active_channel}")
        print(f"  • Joined Channels: {', '.join(sorted(self.node.joined_channels))}")
        print(f"  • Connected Peers: {len(self.node.connected_peers)}")
        print(f"  • Chain Height   : {len(self.node.blockchain.chain)} block(s)")
        print(f"  • PoW Difficulty : {self.node.blockchain.difficulty}")
        print()

    def show_peers(self):
        peers = list(self.node.connected_peers)
        print(c(f"\n👥 Connected Peers ({len(peers)}):", Colors.CYAN + Colors.BOLD))
        if not peers:
            print("  No other peers connected to relay.")
        else:
            for idx, p in enumerate(peers, 1):
                is_rev = p in self.node.revoked_peers
                badge = c("[REVOKED]", Colors.RED) if is_rev else c("[ACTIVE]", Colors.GREEN)
                score = self.node.trust_scores.get(p, 50)
                print(f"  {idx}. {p} {badge} (Trust: {score}/100)")
        print()

    def show_trust_matrix(self):
        matrix = self.node.get_trust_matrix()
        print(c("\n📊 Peer Trust Matrix & On-Chain Verification:", Colors.CYAN + Colors.BOLD))
        print("  " + "-" * 75)
        print(f"  {'Peer ID':<30} {'Trust':<10} {'Status':<25}")
        print("  " + "-" * 75)
        if not matrix:
            print("  No external peers in network.")
        else:
            for item in matrix:
                pid = item["peerId"][:26] + "..." if len(item["peerId"]) > 28 else item["peerId"]
                score = f"{item['score']}/100"
                stat = item["status"]
                if stat == "REVOKED":
                    stat_str = c("🛑 REVOKED (QUARANTINED)", Colors.RED)
                elif stat == "ON_CHAIN_VERIFIED":
                    stat_str = c("✅ ON-CHAIN VERIFIED", Colors.GREEN)
                else:
                    stat_str = c("⚠️ UNREGISTERED", Colors.YELLOW)
                print(f"  {pid:<30} {score:<10} {stat_str}")
        print("  " + "-" * 75 + "\n")

    def show_metrics(self):
        m = self.node.metrics
        print(c("\n⚡ Revocation Efficiency & Cache Performance Metrics:", Colors.CYAN + Colors.BOLD))
        print(f"  • Scoped packets sent          : {c(str(m.get('packets_sent_scoped', 0)), Colors.GREEN)}")
        print(f"  • Revocation packets received  : {c(str(m.get('packets_received_revocation', 0)), Colors.YELLOW)}")
        print(f"  • Lazy cache hits              : {c(str(m.get('cache_hits', 0)), Colors.GREEN)}")
        print(f"  • Lazy cache misses            : {c(str(m.get('cache_misses', 0)), Colors.CYAN)}")
        print(f"  • On-demand chain requests     : {m.get('chain_syncs_on_demand', 0)}")
        print(f"  • Chain request timeouts       : {m.get('chain_sync_timeouts', 0)}")
        total_cache = m.get('cache_hits', 0) + m.get('cache_misses', 0)
        hit_rate = (m.get('cache_hits', 0) / total_cache * 100) if total_cache > 0 else 0.0
        print(f"  • Cache hit rate               : {hit_rate:.1f}%")
        for pid, entry in sorted(self.node.revocation_cache.items()):
            remaining = max(0.0, entry.get("ttl", 300.0) - (time.time() - entry.get("cached_at", 0)))
            print(f"    {pid[:24]}...: {entry['status']} (TTL remaining: {remaining:.0f}s)")
        print()

    def show_blockchain_explorer(self):
        chain = self.node.blockchain.chain
        print(c(f"\n⛓️  Native Blockchain Explorer (Height: {len(chain)} blocks, PoW Difficulty: {self.node.blockchain.difficulty}):", Colors.CYAN + Colors.BOLD))
        for b in reversed(chain):
            b_dict = b.to_dict() if hasattr(b, "to_dict") else b
            idx = b_dict.get("index")
            h = b_dict.get("hash")
            prev_h = b_dict.get("previousHash")
            nonce = b_dict.get("nonce")
            ts = b_dict.get("timestamp")
            dt_str = datetime.fromtimestamp(ts / 1000).strftime("%Y-%m-%d %H:%M:%S") if ts else "N/A"
            txs = b_dict.get("transactions", [])

            print(c(f"  ┌─ Block #{idx} ── Hash: {h[:24]}... ──────────", Colors.CYAN))
            print(f"  │  • Timestamp : {dt_str} ({ts})")
            print(f"  │  • Prev Hash : {prev_h[:24]}...")
            print(f"  │  • Nonce     : {nonce}")
            print(f"  │  • Txs ({len(txs)})  :")
            for tx in txs:
                t_type = tx.get("type")
                sender = tx.get("senderPeerId", "")[:16]
                payload_str = json.dumps(tx.get("payload", {}))
                print(f"  │    - [{c(t_type, Colors.YELLOW)}] Sender: {sender}... | {payload_str}")
            print(c("  └────────────────────────────────────────────────────────", Colors.CYAN))
        print()

    async def lookup_peer(self, query: str):
        if not query:
            print(c("❌ Usage: lookup <peerId>", Colors.RED))
            return
        rec = await self.node.lookup_peer(query)
        if not rec:
            print(c(f"❌ No record found on native blockchain for '{query}'.", Colors.RED))
            return

        print(c("\n📄 Native Blockchain Identity Record:", Colors.CYAN + Colors.BOLD))
        print(f"  • Peer ID     : {rec.get('peerId')}")
        print(f"  • DID URI     : {rec.get('didUri')}")
        print(f"  • Public Key  : {rec.get('publicKeyHex')}")
        is_rev = rec.get("isRevoked")
        if is_rev:
            print(f"  • Status      : {c('🛑 REVOKED ON-CHAIN', Colors.RED + Colors.BOLD)}")
            print(f"  • Revoke Code : {rec.get('reason')}")
        else:
            print(f"  • Status      : {c('✅ ACTIVE (ON-CHAIN)', Colors.GREEN + Colors.BOLD)}")

        created_dt = datetime.fromtimestamp(rec.get("createdAt", 0) / 1000).strftime("%Y-%m-%d %H:%M:%S")
        updated_dt = datetime.fromtimestamp(rec.get("updatedAt", 0) / 1000).strftime("%Y-%m-%d %H:%M:%S")
        print(f"  • Registered  : {created_dt}")
        print(f"  • Last Update : {updated_dt}")

        history = self.node.blockchain.get_key_history(rec.get("peerId", ""))
        print(f"  • Key Versions: {len(history)} version(s) in audit trail")
        for idx, k in enumerate(history, 1):
            print(f"     v{idx}: {k[:32]}...")
        print()

    def swap_crypto_suite(self, hash_name: str, cipher_name: str):
        h_lower = hash_name.lower().replace("-", "").replace("_", "")
        c_lower = cipher_name.lower().replace("-", "").replace("_", "")

        # Hash Provider
        if "blake" in h_lower:
            h_prov = BLAKE2bProvider()
        elif "sha3" in h_lower:
            h_prov = SHA3_256Provider()
        else:
            h_prov = SHA256Provider()

        # Cipher Provider
        if "chacha" in c_lower or "poly" in c_lower:
            c_prov = ChaCha20Poly1305Provider()
        else:
            c_prov = AESGCMProvider()

        new_suite = CryptoSuite(
            hash_provider=h_prov,
            asymmetric_provider=NISTP256Provider(),
            cipher_provider=c_prov
        )
        self.node.set_crypto_suite(new_suite)
        print(c(f"✅ Crypto Suite Hot-Swapped to: {new_suite.get_descriptor()}", Colors.GREEN + Colors.BOLD))

    # ──────────────────────────────────────────────────────────────
    # Interactive Guided Menu
    # ──────────────────────────────────────────────────────────────

    async def run_interactive_menu(self):
        while True:
            print(c("\n┌────────────────────────────────────────────────────────┐", Colors.CYAN))
            print(c("│           SOVEREIGN P2P NODE - FUNCTION MENU           │", Colors.CYAN + Colors.BOLD))
            print(c("├────────────────────────────────────────────────────────┤", Colors.CYAN))
            print("│  [1]  Send Confidential 1-on-1 Direct Message (ECIES)  │")
            print("│  [2]  Send Group Channel Message (Symmetric AEAD)      │")
            print("│  [3]  Send Signed Public Broadcast                     │")
            print("│  [4]  Channel Management (Join / Leave / Switch)       │")
            print("│  [5]  DPKI: Revoke Active Key On-Chain                 │")
            print("│  [6]  DPKI: Reinstate / Unrevoke Key                   │")
            print("│  [7]  DPKI: Rotate Keypair On-Chain                    │")
            print("│  [8]  Blockchain: Lookup Peer Identity Record & History│")
            print("│  [9]  Blockchain Explorer (Blocks & Transactions)      │")
            print("│  [10] Cryptographic Suite Hot-Swap                     │")
            print("│  [11] View Trust Matrix & Connected Peers              │")
            print("│  [12] View Scoped Gossip & Cache Metrics               │")
            print("│  [13] Node Status Dashboard                            │")
            print("│  [0]  Return to CLI                                    │")
            print(c("└────────────────────────────────────────────────────────┘", Colors.CYAN))

            sys.stdout.write(c("Select option [0-13]: ", Colors.YELLOW + Colors.BOLD))
            sys.stdout.flush()
            loop = asyncio.get_running_loop()
            line = await loop.run_in_executor(None, sys.stdin.readline)
            choice = line.strip()

            if choice == "0" or not choice:
                print(c("Returned to CLI command mode.", Colors.DIM))
                break

            elif choice == "1":
                peers = list(self.node.connected_peers)
                if peers:
                    print(c("Connected peers:", Colors.CYAN))
                    for i, p in enumerate(peers, 1):
                        print(f"  {i}. {p}")
                sys.stdout.write("Recipient Peer ID (or prefix): ")
                sys.stdout.flush()
                recip = (await loop.run_in_executor(None, sys.stdin.readline)).strip()
                if not recip:
                    continue
                # Match prefix
                matched = next((p for p in self.node.connected_peers if p.startswith(recip)), recip)
                sys.stdout.write("Confidential message text: ")
                sys.stdout.flush()
                msg = (await loop.run_in_executor(None, sys.stdin.readline)).strip()
                if msg:
                    res = await self.node.send_direct_message(matched, msg)
                    if res.get("success"):
                        print(c(f"✅ Confidential message encrypted with {self.node.crypto_suite.cipher_provider.name} and sent!", Colors.GREEN))
                    else:
                        print(c(f"❌ Failed: {res.get('error')}", Colors.RED))

            elif choice == "2":
                print(c(f"Joined channels: {', '.join(sorted(self.node.joined_channels))}", Colors.CYAN))
                sys.stdout.write(f"Target channel (press Enter for {self.node.active_channel}): ")
                sys.stdout.flush()
                ch = (await loop.run_in_executor(None, sys.stdin.readline)).strip()
                target_ch = ch if ch else self.node.active_channel
                sys.stdout.write(f"Channel message for {target_ch}: ")
                sys.stdout.flush()
                msg = (await loop.run_in_executor(None, sys.stdin.readline)).strip()
                if msg:
                    res = await self.node.send_channel_message(target_ch, msg)
                    if res.get("success"):
                        print(c(f"✅ Encrypted channel message dispatched to {target_ch}!", Colors.GREEN))
                    else:
                        print(c(f"❌ Failed: {res.get('error')}", Colors.RED))

            elif choice == "3":
                sys.stdout.write("Public broadcast message: ")
                sys.stdout.flush()
                msg = (await loop.run_in_executor(None, sys.stdin.readline)).strip()
                if msg:
                    result = await self.node.send_broadcast(msg)
                    if result.get("success"):
                        print(c("✅ Signed broadcast dispatched to all peers!", Colors.GREEN))
                    else:
                        print(c(f"❌ Failed: {result.get('error')}", Colors.RED))

            elif choice == "4":
                print(f"Currently joined: {', '.join(sorted(self.node.joined_channels))}")
                print(f"Active channel  : {self.node.active_channel}")
                print("1. Join Channel\n2. Leave Channel\n3. Switch Active Channel")
                sys.stdout.write("Select [1-3]: ")
                sys.stdout.flush()
                sub = (await loop.run_in_executor(None, sys.stdin.readline)).strip()
                if sub == "1":
                    sys.stdout.write("Channel name to join (e.g. #secops): ")
                    sys.stdout.flush()
                    ch = (await loop.run_in_executor(None, sys.stdin.readline)).strip()
                    if ch:
                        await self.node.join_channel(ch)
                        print(c(f"✅ Joined {ch}!", Colors.GREEN))
                elif sub == "2":
                    sys.stdout.write("Channel name to leave: ")
                    sys.stdout.flush()
                    ch = (await loop.run_in_executor(None, sys.stdin.readline)).strip()
                    if ch:
                        await self.node.leave_channel(ch)
                        print(c(f"✅ Left {ch}!", Colors.YELLOW))
                elif sub == "3":
                    sys.stdout.write("Channel to switch active to: ")
                    sys.stdout.flush()
                    ch = (await loop.run_in_executor(None, sys.stdin.readline)).strip()
                    if ch:
                        if not ch.startswith("#"):
                            ch = "#" + ch
                        self.node.active_channel = ch
                        if ch not in self.node.joined_channels:
                            await self.node.join_channel(ch)
                        print(c(f"🎯 Switched active target channel to {ch}", Colors.CYAN))

            elif choice == "5":
                print(c("\nSelect Revocation Reason Code:", Colors.YELLOW))
                print("1 - Key Compromise")
                print("2 - Superseded")
                print("3 - Decommissioned")
                print("4 - Malicious Activity")
                sys.stdout.write("Choice [1-4, default 1]: ")
                sys.stdout.flush()
                r_code = (await loop.run_in_executor(None, sys.stdin.readline)).strip()
                reason = int(r_code) if r_code in ("1", "2", "3", "4") else 1
                res = await self.node.revoke_key(reason=reason)
                if res.get("success"):
                    print(c("🛑 Identity successfully marked REVOKED on blockchain!", Colors.RED + Colors.BOLD))
                else:
                    print(c(f"❌ Revocation failed: {res.get('error')}", Colors.RED))

            elif choice == "6":
                res = await self.node.unrevoke_key()
                if res.get("success"):
                    print(c("♻️  Identity successfully REINSTATED on blockchain!", Colors.GREEN + Colors.BOLD))
                else:
                    print(c(f"❌ Reinstate failed: {res.get('error')}", Colors.RED))

            elif choice == "7":
                res = await self.node.rotate_key()
                if res.get("success"):
                    print(c(f"✅ Keypair rotated on blockchain! New PubKey: {self.node.public_key[:32]}...", Colors.MAGENTA + Colors.BOLD))
                else:
                    print(c(f"❌ Rotation failed: {res.get('error')}", Colors.RED))

            elif choice == "8":
                sys.stdout.write("Peer ID to lookup (full or prefix): ")
                sys.stdout.flush()
                q = (await loop.run_in_executor(None, sys.stdin.readline)).strip()
                if q:
                    await self.lookup_peer(q)

            elif choice == "9":
                self.show_blockchain_explorer()

            elif choice == "10":
                print(c("\nActive Suite: " + self.node.crypto_suite.get_descriptor(), Colors.MAGENTA))
                print("Select Hash Provider:\n  1. SHA-256\n  2. BLAKE2b-256\n  3. SHA3-256")
                sys.stdout.write("Choice [1-3, default 1]: ")
                sys.stdout.flush()
                h_choice = (await loop.run_in_executor(None, sys.stdin.readline)).strip()
                h_map = {"1": "sha256", "2": "blake2b", "3": "sha3"}
                h_val = h_map.get(h_choice, "sha256")

                print("Select Symmetric Cipher:\n  1. AES-256-GCM\n  2. ChaCha20-Poly1305")
                sys.stdout.write("Choice [1-2, default 1]: ")
                sys.stdout.flush()
                c_choice = (await loop.run_in_executor(None, sys.stdin.readline)).strip()
                c_map = {"1": "aes-gcm", "2": "chacha20"}
                c_val = c_map.get(c_choice, "aes-gcm")

                self.swap_crypto_suite(h_val, c_val)

            elif choice == "11":
                self.show_peers()
                self.show_trust_matrix()

            elif choice == "12":
                self.show_metrics()

            elif choice == "13":
                self.show_status()

    # ──────────────────────────────────────────────────────────────
    # Main CLI Loop
    # ──────────────────────────────────────────────────────────────

    async def cli_loop(self):
        loop = asyncio.get_running_loop()

        while self._running:
            self._print_prompt()
            try:
                line = await loop.run_in_executor(None, sys.stdin.readline)
                if not line:
                    break
                cmd = line.strip()
                if not cmd:
                    continue

                # 1. Menu
                if cmd == "menu":
                    await self.run_interactive_menu()
                    continue

                # 2. Help
                if cmd == "help":
                    self.show_help()
                    continue

                # 3. Status
                if cmd == "status":
                    self.show_status()
                    continue

                # 4. Peers
                if cmd == "peers":
                    self.show_peers()
                    continue

                # 5. Trust
                if cmd == "trust":
                    self.show_trust_matrix()
                    continue

                # 6. Metrics
                if cmd == "metrics":
                    self.show_metrics()
                    continue

                # 7. Blockchain Explorer
                if cmd in ("chain", "blocks"):
                    self.show_blockchain_explorer()
                    continue

                # 8. Clear
                if cmd == "clear":
                    os.system("cls" if os.name == "nt" else "clear")
                    self.print_banner()
                    continue

                # 9. Exit
                if cmd in ("exit", "quit"):
                    print(c("Shutting down node...", Colors.YELLOW))
                    break

                # 10. Lookup
                if cmd.startswith("refresh "):
                    target = cmd.split(maxsplit=1)[1].strip()
                    matches = [pid for pid in self.node.connected_peers if pid.startswith(target)]
                    if len(matches) != 1:
                        print(c("❌ Use a full peer ID or a prefix matching exactly one connected peer.", Colors.RED))
                    else:
                        result = await self.node.verify_peer_revocation_lazy(matches[0], force_refresh=True)
                        print(c(f"Current key status: {result['status']}", Colors.CYAN))
                    continue

                if cmd.startswith("lookup"):
                    parts = cmd.split(maxsplit=1)
                    q = parts[1] if len(parts) > 1 else ""
                    await self.lookup_peer(q)
                    continue

                # 11. DPKI Revoke
                if cmd.startswith("revoke"):
                    parts = cmd.split()
                    reason = 1
                    if len(parts) > 1 and parts[1].isdigit() and 1 <= int(parts[1]) <= 4:
                        reason = int(parts[1])
                    res = await self.node.revoke_key(reason=reason)
                    if res.get("success"):
                        print(c("🛑 Identity marked REVOKED on native blockchain! Scoped update sent to contacts.", Colors.RED + Colors.BOLD))
                    else:
                        print(c(f"❌ Revocation failed: {res.get('error')}", Colors.RED))
                    continue

                # 12. DPKI Unrevoke
                if cmd in ("unrevoke", "reinstate"):
                    res = await self.node.unrevoke_key()
                    if res.get("success"):
                        print(c("♻️  Identity REINSTATED on native blockchain! Scoped update sent to contacts.", Colors.GREEN + Colors.BOLD))
                    else:
                        print(c(f"❌ Reinstate failed: {res.get('error')}", Colors.RED))
                    continue

                # 13. DPKI Rotate
                if cmd == "rotate":
                    res = await self.node.rotate_key()
                    if res.get("success"):
                        print(c(f"✅ Key rotated on blockchain! New PubKey: {self.node.public_key[:32]}...", Colors.MAGENTA + Colors.BOLD))
                    else:
                        print(c(f"❌ Rotation failed: {res.get('error')}", Colors.RED))
                    continue

                # 14. Crypto Suite
                if cmd.startswith("crypto"):
                    parts = cmd.split()
                    if len(parts) == 1:
                        print(c(f"Active Suite: {self.node.crypto_suite.get_descriptor()}", Colors.MAGENTA))
                    elif len(parts) >= 3:
                        self.swap_crypto_suite(parts[1], parts[2])
                    else:
                        print(c("Usage: crypto <hash> <cipher> (e.g. 'crypto blake2b chacha20')", Colors.YELLOW))
                    continue

                # 15. Channel commands
                if cmd.startswith("join "):
                    ch = cmd.split(maxsplit=1)[1].strip()
                    await self.node.join_channel(ch)
                    print(c(f"✅ Joined channel {self.node.active_channel}!", Colors.GREEN))
                    continue

                if cmd.startswith("leave "):
                    ch = cmd.split(maxsplit=1)[1].strip()
                    await self.node.leave_channel(ch)
                    print(c(f"Left channel {ch}. Active is now {self.node.active_channel}.", Colors.YELLOW))
                    continue

                if cmd.startswith("channel "):
                    ch = cmd.split(maxsplit=1)[1].strip()
                    if not ch.startswith("#"):
                        ch = "#" + ch
                    self.node.active_channel = ch
                    if ch not in self.node.joined_channels:
                        await self.node.join_channel(ch)
                    print(c(f"🎯 Switched active target channel to {ch}", Colors.CYAN))
                    continue

                if cmd == "channels":
                    print(f"Joined channels: {', '.join(sorted(self.node.joined_channels))}")
                    print(f"Active channel : {self.node.active_channel}")
                    continue

                # 16. Broadcast
                if cmd.startswith("broadcast "):
                    msg = cmd.split(maxsplit=1)[1].strip()
                    result = await self.node.send_broadcast(msg)
                    if result.get("success"):
                        print(c("📤 Broadcast dispatched!", Colors.BLUE))
                    else:
                        print(c(f"❌ Failed: {result.get('error')}", Colors.RED))
                    continue

                # 17. Direct Message: @<peerId> <msg> or dm <peerId> <msg>
                if cmd.startswith("@") or cmd.startswith("dm "):
                    if cmd.startswith("@"):
                        parts = cmd[1:].split(" ", 1)
                        target = parts[0]
                        text = parts[1] if len(parts) > 1 else ""
                    else:
                        parts = cmd.split(" ", 2)
                        target = parts[1] if len(parts) > 1 else ""
                        text = parts[2] if len(parts) > 2 else ""

                    if not target or not text:
                        print(c("Usage: @<peerId> <message> or dm <peerId> <message>", Colors.YELLOW))
                        continue

                    # Match prefix
                    matched = next((p for p in self.node.connected_peers if p.startswith(target)), target)
                    res = await self.node.send_direct_message(matched, text)
                    if res.get("success"):
                        ts = datetime.now().strftime("%H:%M:%S")
                        print(f"{c(f'[{ts}] 🔒 [YOU ➔ @{matched[:16]}... (ECIES)]', Colors.GREEN + Colors.BOLD)} {c(text, Colors.WHITE)}")
                    else:
                        print(c(f"❌ DM failed: {res.get('error')}", Colors.RED))
                    continue

                # 18. Channel Message: #<channel> <msg>
                if cmd.startswith("#"):
                    parts = cmd.split(" ", 1)
                    ch = parts[0]
                    text = parts[1] if len(parts) > 1 else ""
                    if not text:
                        self.node.active_channel = ch
                        if ch not in self.node.joined_channels:
                            await self.node.join_channel(ch)
                        print(c(f"🎯 Switched active target channel to: {ch}", Colors.CYAN))
                        continue
                    if ch not in self.node.joined_channels:
                        await self.node.join_channel(ch)
                    res = await self.node.send_channel_message(ch, text)
                    if res.get("success"):
                        ts = datetime.now().strftime("%H:%M:%S")
                        peer_count = len(self.node.connected_peers)
                        print(f"{c(f'[{ts}] 📢 [YOU ➔ {ch}]', Colors.CYAN + Colors.BOLD)} {c(text, Colors.WHITE)}")
                        if peer_count == 0:
                            print(c(f"  ⚠️ (Notice: 0 other peers currently connected to relay)", Colors.YELLOW + Colors.DIM))
                    else:
                        print(c(f"❌ Failed: {res.get('error')}", Colors.RED))
                    continue

                # 19. Default: Send to active channel
                res = await self.node.send_channel_message(self.node.active_channel, cmd)
                if res.get("success"):
                    ts = datetime.now().strftime("%H:%M:%S")
                    ch = self.node.active_channel
                    peer_count = len(self.node.connected_peers)
                    print(f"{c(f'[{ts}] 📢 [YOU ➔ {ch}]', Colors.CYAN + Colors.BOLD)} {c(cmd, Colors.WHITE)}")
                    if peer_count == 0:
                        print(c(f"  ⚠️ (Notice: 0 other peers currently connected to relay)", Colors.YELLOW + Colors.DIM))
                else:
                    print(c(f"❌ Failed: {res.get('error')}", Colors.RED))

            except (asyncio.CancelledError, KeyboardInterrupt):
                break
            except Exception as e:
                print(c(f"⚠️ Error: {e}", Colors.RED))

    async def start(self):
        self._running = True
        self.print_banner()

        # Connect node to relay and register on chain
        print(c("🔗 Initializing sovereign node and connecting to relay...", Colors.CYAN))
        connected = await self.node.start()
        if not connected:
            print(c(f"⚠️ Could not reach relay at {self.relay_host}:{self.relay_port}. Running in standalone offline mode.", Colors.YELLOW))
        else:
            print(c(f"✅ Connected to relay at {self.relay_host}:{self.relay_port}!", Colors.GREEN))

        try:
            await self.cli_loop()
        finally:
            await self.node.stop()
        print(c("\n👋 Sovereign Node shutdown cleanly.", Colors.CYAN))


# ──────────────────────────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="P2P Sovereign Node CLI (Pure Terminal, Zero UI)")
    parser.add_argument("--relay", default=os.environ.get("RELAY_ADDR", "127.0.0.1:4001"),
                        help="Relay host:port (e.g. 127.0.0.1:4001 or 192.168.1.100:4001)")
    parser.add_argument("--port", type=int, default=None,
                        help="Port identifier for peer identity file (e.g. 8501 -> peer_identity_8501.json)")
    parser.add_argument("--id-file", default=None,
                        help="Custom identity file path (e.g. alice_identity.json)")
    parser.add_argument("--peer-id", default=os.environ.get("PEER_ID"),
                        help="Custom Peer ID override")
    parser.add_argument("--channel", default="#general",
                        help="Initial active channel (default: #general)")
    args = parser.parse_args()

    relay_host, relay_port = args.relay.split(":") if ":" in args.relay else (args.relay, 4001)
    relay_port = int(relay_port)

    # Determine identity file
    identity_file = args.id_file
    if not identity_file and args.port:
        identity_file = f"peer_identity_{args.port}.json"
    elif not identity_file:
        identity_file = "peer_identity_cli.json"

    cli = PeerNodeCLI(
        relay_host=relay_host,
        relay_port=relay_port,
        identity_file=identity_file,
        peer_id=args.peer_id,
        initial_channel=args.channel
    )

    try:
        asyncio.run(cli.start())
    except KeyboardInterrupt:
        print("\nExiting.")


if __name__ == "__main__":
    main()
