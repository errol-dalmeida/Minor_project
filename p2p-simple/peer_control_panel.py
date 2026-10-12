import asyncio
import os
import sys
import threading
import time
from typing import Optional

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import streamlit as st

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

# Page Configuration
st.set_page_config(
    page_title="P2P Sovereign Node Control Panel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────────────────────────
# Background Thread & Asyncio Node Manager (Decentralized & Isolated)
# ─────────────────────────────────────────────────────────────────

class NodeThreadManager:
    def __init__(self, relay_host="127.0.0.1", relay_port=4001, identity_file=None):
        self.loop = asyncio.new_event_loop()
        self.node = PeerNode(
            relay_host=relay_host,
            relay_port=relay_port,
            identity_file=identity_file
        )
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        # Start node
        future = asyncio.run_coroutine_threadsafe(self.node.start(), self.loop)
        future.result(timeout=5)

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def run_sync(self, coro, timeout=10):
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return future.result(timeout=timeout)


@st.cache_resource(show_spinner=False)
def get_node_manager(server_port: int, relay_host: str, relay_port: int) -> NodeThreadManager:
    identity_file = f"peer_identity_{server_port}.json"
    return NodeThreadManager(relay_host=relay_host, relay_port=relay_port, identity_file=identity_file)


# Determine port and relay configuration
try:
    server_port = int(st.get_option("server.port") or 8501)
except Exception:
    server_port = 8501

relay_env = os.environ.get("RELAY_ADDR", "127.0.0.1:4001")
r_host, r_port = relay_env.split(":") if ":" in relay_env else ("127.0.0.1", 4001)

node_mgr: NodeThreadManager = get_node_manager(server_port, r_host, int(r_port))
node: PeerNode = node_mgr.node


# ─────────────────────────────────────────────────────────────────
# Sidebar: Sovereign Node Status & Hot-Swap Cryptographic Suite
# ─────────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("🛡️ Peer Node Sovereign Identity")
    st.caption("Zero-Trust Decentralized Control Panel")

    st.markdown(f"**Peer ID**: `{node.peer_id[:18]}...`")
    st.markdown(f"**DID**: `{node.did['id']}`")
    is_revoked = node.peer_id in node.revoked_peers
    if is_revoked:
        st.error("🛑 IDENTITY STATUS: REVOKED ON-CHAIN")
    else:
        st.success("✅ IDENTITY STATUS: ACTIVE (ON-CHAIN)")

    st.divider()

    # Hot-Swap Cryptographic Suite
    st.subheader("⚙️ Cryptographic Suite")
    st.info(f"**Active**:\n{node.crypto_suite.get_descriptor()}")

    hash_choice = st.selectbox("Hash Strategy", ["SHA-256", "BLAKE2b-256", "SHA3-256"])
    cipher_choice = st.selectbox("Symmetric Cipher", ["AES-256-GCM", "ChaCha20-Poly1305"])

    if st.button("Apply Modular Crypto Suite", use_container_width=True):
        # Select Hash Provider
        if hash_choice == "BLAKE2b-256":
            h_prov = BLAKE2bProvider()
        elif hash_choice == "SHA3-256":
            h_prov = SHA3_256Provider()
        else:
            h_prov = SHA256Provider()

        # Select Cipher Provider
        if cipher_choice == "ChaCha20-Poly1305":
            c_prov = ChaCha20Poly1305Provider()
        else:
            c_prov = AESGCMProvider()

        new_suite = CryptoSuite(
            hash_provider=h_prov,
            asymmetric_provider=NISTP256Provider(),
            cipher_provider=c_prov
        )
        node.set_crypto_suite(new_suite)
        st.success("Crypto Suite Hot-Swapped!")
        st.rerun()

    st.divider()

    # DPKI Lifecycle Actions
    st.subheader("⛓️ DPKI Lifecycle Actions")

    col_rev, col_unrev = st.columns(2)
    with col_rev:
        reason_select = st.selectbox("Revoke Reason", [
            ("1 - Key Compromise", RevocationReason.KEY_COMPROMISE),
            ("2 - Superseded", RevocationReason.SUPERSEDED),
            ("3 - Decommissioned", RevocationReason.DECOMMISSIONED),
            ("4 - Malicious", RevocationReason.MALICIOUS_ACTIVITY)
        ], format_func=lambda x: x[0])
        if st.button("🛑 Revoke Key", use_container_width=True):
            res = node_mgr.run_sync(node.revoke_key(reason=reason_select[1]))
            if res.get("success"):
                st.warning("Identity marked REVOKED on-chain!")
                st.rerun()

    with col_unrev:
        st.write("")
        st.write("")
        if st.button("♻️ Reinstate", use_container_width=True):
            res = node_mgr.run_sync(node.unrevoke_key())
            if res.get("success"):
                st.success("Identity Reinstated!")
                st.rerun()

    if st.button("🔄 Rotate Keypair On-Chain", use_container_width=True):
        res = node_mgr.run_sync(node.rotate_key())
        if res.get("success"):
            st.success("Key rotated on blockchain!")
            st.rerun()
        else:
            st.error(f"Rotation failed: {res.get('error')}")


# ─────────────────────────────────────────────────────────────────
# Main Interface: Tabs
# ─────────────────────────────────────────────────────────────────

st.title("🎛️ Peer Operations & Function Selector")

tab_ops, tab_messages, tab_trust, tab_chain, tab_logs = st.tabs([
    "🚀 Execute Functions",
    "💬 Message Inbox",
    "📊 Trust Matrix",
    "⛓️ Blockchain Explorer",
    "📜 Activity Log"
])

# ── TAB 1: FUNCTION SELECTOR & EXECUTION ──────────────────────────
with tab_ops:
    st.subheader("Select and Execute Function through Code")

    func_choice = st.selectbox("Select Function to Execute:", [
        "1. Send Confidential 1-on-1 Direct Message (ECIES)",
        "2. Send Group Channel Message (Symmetric AEAD)",
        "3. Join / Switch Group Channel",
        "4. Send Signed Public Broadcast",
        "5. Lookup Peer on Native Blockchain"
    ])

    # Connected Peers list for dropdown
    connected_list = list(node.connected_peers)
    peer_options = connected_list if connected_list else ["No other peers connected yet"]

    if func_choice.startswith("1."):
        st.markdown("#### 🔒 1-on-1 End-to-End Encrypted Direct Message (ECIES)")
        st.caption("Message will be encrypted using ECDH + HKDF + AES-GCM/ChaCha20 and digitally signed with ECDSA.")

        selected_recipient = st.selectbox("Recipient Peer ID:", peer_options, key="dm_recipient")
        dm_input = st.text_area("Message Content:", placeholder="Type confidential message here...", key="dm_text")

        if st.button("🚀 Send E2EE Direct Message", type="primary"):
            if not dm_input.strip():
                st.warning("Please enter a message.")
            elif selected_recipient not in connected_list:
                st.error("No active connected peer selected.")
            else:
                res = node_mgr.run_sync(node.send_direct_message(selected_recipient, dm_input.strip()))
                if res.get("success"):
                    st.success(f"Message encrypted with {node.crypto_suite.cipher_provider.name} and delivered!")
                    st.rerun()
                else:
                    st.error(f"Delivery failed: {res.get('error')}")

    elif func_choice.startswith("2."):
        st.markdown("#### 📢 Group Channel Messaging")
        st.caption("Message is encrypted symmetrically with the shared channel key and signed by your private key.")

        channel_options = list(node.joined_channels)
        selected_channel = st.selectbox("Target Channel:", channel_options, key="ch_select")
        ch_input = st.text_area("Channel Message:", placeholder="Type channel message here...", key="ch_text")

        if st.button("📢 Send Channel Message", type="primary"):
            if not ch_input.strip():
                st.warning("Please enter a message.")
            else:
                res = node_mgr.run_sync(node.send_channel_message(selected_channel, ch_input.strip()))
                if res.get("success"):
                    st.success(f"Encrypted message sent to {selected_channel}!")
                    st.rerun()
                else:
                    st.error(f"Failed: {res.get('error')}")

    elif func_choice.startswith("3."):
        st.markdown("#### 👥 Channel Membership Management")
        st.markdown(f"**Currently Joined**: `{', '.join(node.joined_channels)}`")

        new_ch = st.text_input("Channel Name to Join (e.g. #dev, #finance):", value="#secops")
        col_j, col_l = st.columns(2)
        with col_j:
            if st.button("➕ Join / Create Channel", use_container_width=True):
                if new_ch.strip():
                    node_mgr.run_sync(node.join_channel(new_ch.strip()))
                    st.success(f"Joined {new_ch.strip()}!")
                    st.rerun()
        with col_l:
            if st.button("➖ Leave Channel", use_container_width=True):
                if new_ch.strip():
                    node_mgr.run_sync(node.leave_channel(new_ch.strip()))
                    st.info(f"Left {new_ch.strip()}!")
                    st.rerun()

    elif func_choice.startswith("4."):
        st.markdown("#### 📤 Public Signed Broadcast")
        st.caption("Plaintext broadcast verified against your public key on the native blockchain.")
        b_input = st.text_area("Broadcast Message:", placeholder="Public announcement...", key="b_text")
        if st.button("📤 Send Broadcast", type="primary"):
            if b_input.strip():
                node_mgr.run_sync(node.send_broadcast(b_input.strip()))
                st.success("Broadcast dispatched!")
                st.rerun()

    elif func_choice.startswith("5."):
        st.markdown("#### 🔍 On-Chain Identity Audit & History Lookup")
        lookup_id = st.text_input("Enter Peer ID prefix or full ID:", key="lookup_query")
        if st.button("🔍 Query Blockchain"):
            if lookup_id.strip():
                rec = node_mgr.run_sync(node.lookup_peer(lookup_id.strip()))
                if rec:
                    st.json(rec)
                    history = node.blockchain.get_key_history(rec.get("peerId", ""))
                    st.markdown(f"**Key Rotation History**: `{len(history)} version(s)`")
                    for idx, k in enumerate(history):
                        st.code(f"Version #{idx + 1}: {k}")
                else:
                    st.error("No record found on native blockchain.")


# ── TAB 2: MESSAGE INBOX ──────────────────────────────────────────
with tab_messages:
    st.subheader("💬 Decrypted Message History")
    col_ref, _ = st.columns([1, 4])
    with col_ref:
        if st.button("🔄 Refresh Feed"):
            st.rerun()

    if not node.message_history:
        st.info("No messages received or sent yet.")
    else:
        for m in reversed(node.message_history):
            is_incoming = "INCOMING" in m["kind"]
            badge_color = "green" if is_incoming else "blue"
            with st.container():
                st.markdown(
                    f"**[{m['timestamp']}]** :{badge_color}[`{m['kind']}`] &nbsp;|&nbsp; "
                    f"**From:** `{m['sender'][:16]}...` &nbsp;➔&nbsp; **To:** `{m['target'][:16]}...` &nbsp;|&nbsp; "
                    f"*{m['mode']}*"
                )
                st.markdown(f"> **{m['text']}**")
                st.divider()


# ── TAB 3: TRUST MATRIX ───────────────────────────────────────────
with tab_trust:
    st.subheader("📊 Dynamic Peer Trust Matrix & On-Chain Verification")
    st.caption("Trust scores (0–100) are adjusted automatically based on cryptographic signature verification and on-chain status.")

    matrix = node.get_trust_matrix()
    if not matrix:
        st.info("No external peers connected to relay.")
    else:
        for p in matrix:
            score = p["score"]
            status = p["status"]

            col_id, col_bar, col_stat = st.columns([3, 4, 3])
            with col_id:
                st.code(p["peerId"])
            with col_bar:
                st.progress(score / 100.0, text=f"Trust Score: {score}/100")
            with col_stat:
                if status == "REVOKED":
                    st.error("🛑 REVOKED ON-CHAIN (QUARANTINED)")
                elif status == "ON_CHAIN_VERIFIED":
                    st.success("✅ ON-CHAIN VERIFIED")
                else:
                    st.warning("⚠️ UNREGISTERED ON-CHAIN")


# ── TAB 4: BLOCKCHAIN EXPLORER ────────────────────────────────────
with tab_chain:
    st.subheader("⛓️ Native In-Code Blockchain Explorer")
    blocks = node.get_blockchain_history()
    st.markdown(f"**Chain Height**: `{len(blocks)} block(s)` &nbsp;|&nbsp; **Difficulty**: `{node.blockchain.difficulty}` (Proof-of-Work)")

    for b in reversed(blocks):
        with st.expander(f"Block #{b['index']} — Hash: {b['hash'][:24]}... (Transactions: {len(b['transactions'])})"):
            st.markdown(f"- **Previous Hash**: `{b['previousHash']}`")
            st.markdown(f"- **Nonce**: `{b['nonce']}`")
            st.markdown(f"- **Timestamp**: `{b['timestamp']}`")
            st.markdown("##### Transactions in Block:")
            for tx in b["transactions"]:
                st.code(f"Type: {tx.get('type')} | Sender: {tx.get('senderPeerId')}\nPayload: {tx.get('payload')}")


# ── TAB 5: ACTIVITY LOG ───────────────────────────────────────────
with tab_logs:
    st.subheader("📜 Peer Node Real-Time Activity Log")
    if not node.event_log:
        st.info("No events logged.")
    else:
        st.code("\n".join(reversed(node.event_log)), language="bash")
