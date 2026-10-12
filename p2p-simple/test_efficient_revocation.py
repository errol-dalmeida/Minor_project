"""
═══════════════════════════════════════════════════════════════════════════
  EFFICIENT REVOCATION BENCHMARK — Scoped Gossip vs. Broadcast Flooding
═══════════════════════════════════════════════════════════════════════════

  Network Topology:
    Alice ──── #dev ──── Bob        (active contacts)
    Charlie ── #marketing ── Dave   (strangers to Alice)

  Phase 1: Packet Count Benchmark
    Alice revokes → Bob gets 1 scoped packet → Charlie & Dave get 0.
    Old broadcast would have sent O(N) = 3 packets.

  Phase 2: On-Demand Lazy Verification
    Charlie tries to DM Alice → lazy check → discovers REVOKED → blocks.

  Phase 3: Cache Performance
    Repeated lazy checks hit TTL cache in sub-millisecond time.

═══════════════════════════════════════════════════════════════════════════
"""

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

from peer_node import PeerNode
from blockchain import RevocationReason
import relay


# ─── Test Utilities ──────────────────────────────────────────────────────

PASS = "✅"
FAIL = "❌"
results = []


def assert_test(name: str, condition: bool, detail: str = ""):
    tag = PASS if condition else FAIL
    msg = f"  {tag} {name}"
    if detail:
        msg += f"  →  {detail}"
    print(msg)
    results.append((name, condition))
    if not condition:
        raise AssertionError(f"TEST FAILED: {name} — {detail}")


# ─── Relay Packet Sniffer ───────────────────────────────────────────────

class PacketSniffer:
    """
    Wraps a PeerNode's relay listener to count /chain/tx/1.0.0 packets
    received by each peer. This is the 'wire-level' counter that proves
    scoped delivery.
    """
    def __init__(self):
        self.revocation_packets: dict[str, int] = {}   # peerId → count

    def reset(self):
        self.revocation_packets.clear()

    def record(self, peer_id: str, msg: dict):
        if msg.get("protocol") == "/chain/tx/1.0.0":
            data = msg.get("data", {})
            if data.get("type") == "REVOKE_KEY":
                self.revocation_packets[peer_id] = self.revocation_packets.get(peer_id, 0) + 1


sniffer = PacketSniffer()


# ─── Patched Relay Listener (Instrumented with Sniffer) ─────────────────

def make_instrumented_listener(node: PeerNode):
    """
    Returns a coroutine that reads from the relay like the normal listener,
    but also feeds every incoming ROUTED_MSG into the PacketSniffer before
    dispatching it to the node's protocol handler.
    """
    original_dispatch = node._dispatch_protocol

    async def instrumented_dispatch(msg: dict):
        sniffer.record(node.peer_id, msg)
        await original_dispatch(msg)

    node._dispatch_protocol = instrumented_dispatch


# ─── Main Benchmark ─────────────────────────────────────────────────────

async def run_benchmark():
    print("═" * 70)
    print("  🔬 EFFICIENT REVOCATION BENCHMARK")
    print("     Scoped Gossip vs. Broadcast Flooding")
    print("═" * 70)
    print()

    # ── 0. Start Isolated Test Relay ────────────────────────────────────
    test_relay_port = 4099
    # Clear any stale state in relay module
    relay.active_peers.clear()
    server = await asyncio.start_server(relay.handle_client, "127.0.0.1", test_relay_port)
    print(f"  🌐 Test relay started on 127.0.0.1:{test_relay_port}")

    # ── 1. Create 4 PeerNodes ───────────────────────────────────────────
    alice = PeerNode(peer_id="Alice_Node_001", relay_port=test_relay_port, auto_register_blockchain=True)
    bob   = PeerNode(peer_id="Bob_Node_002",   relay_port=test_relay_port, auto_register_blockchain=True)
    charlie = PeerNode(peer_id="Charlie_Node_003", relay_port=test_relay_port, auto_register_blockchain=True)
    dave  = PeerNode(peer_id="Dave_Node_004",  relay_port=test_relay_port, auto_register_blockchain=True)

    nodes = [alice, bob, charlie, dave]
    node_names = {alice.peer_id: "Alice", bob.peer_id: "Bob",
                  charlie.peer_id: "Charlie", dave.peer_id: "Dave"}

    # Instrument all nodes with packet sniffer
    for node in nodes:
        make_instrumented_listener(node)

    # ── 2. Start All Nodes (connect to relay) ───────────────────────────
    print("\n  ⚡ Starting nodes...\n")
    for node in nodes:
        await node.start()
        await asyncio.sleep(0.3)

    # Allow relay PEER_LIST and PEER_JOINED exchanges to settle
    await asyncio.sleep(2.0)
    print()

    # ── 3. Build Interaction Graph ──────────────────────────────────────
    # Alice and Bob share channel #dev  →  they are active contacts
    # Charlie and Dave share channel #marketing  →  strangers to Alice
    print("  📊 Building Interaction Graph...")
    print("     Alice ←→ Bob via #dev")
    print("     Charlie ←→ Dave via #marketing")
    print("     Alice has NO interaction with Charlie or Dave\n")

    # Alice joins #dev and announces
    await alice.join_channel("#dev")
    await bob.join_channel("#dev")
    await asyncio.sleep(0.5)

    # Initialize channel_members sets and register membership
    alice.channel_members.setdefault("#dev", set()).add(bob.peer_id)
    bob.channel_members.setdefault("#dev", set()).add(alice.peer_id)

    # Charlie and Dave share #marketing (no overlap with Alice)
    await charlie.join_channel("#marketing")
    await dave.join_channel("#marketing")
    await asyncio.sleep(0.5)
    charlie.channel_members.setdefault("#marketing", set()).add(dave.peer_id)
    dave.channel_members.setdefault("#marketing", set()).add(charlie.peer_id)

    # Cross-register keys so nodes can resolve each other on-chain
    for src in nodes:
        for dst in nodes:
            if src.peer_id != dst.peer_id:
                dst.key_registry[src.peer_id] = src.public_key
                # Register src on dst's local chain
                await dst.blockchain.register_key(
                    src.peer_id, src.public_key,
                    f"did:peer:{src.peer_id}", src.private_key
                )

    # Verify interaction graph scoping
    alice_contacts = alice.get_active_contacts()
    print(f"  Alice's active contacts: {[node_names.get(c, c) for c in alice_contacts]}")
    assert_test(
        "Alice's contact graph includes Bob",
        bob.peer_id in alice_contacts,
        f"Contacts: {[node_names.get(c, c) for c in alice_contacts]}"
    )

    # ════════════════════════════════════════════════════════════════════
    #  PHASE 1: Network Congestion & Packet Counter Benchmark
    # ════════════════════════════════════════════════════════════════════
    print()
    print("─" * 70)
    print("  PHASE 1: Network Congestion & Packet Counter Benchmark")
    print("─" * 70)
    print()

    # Reset sniffer before revocation
    sniffer.reset()
    alice_metrics_before = alice.metrics["packets_sent_scoped"]

    # Alice revokes her key
    print("  🛑 Alice revokes her key on the blockchain...")
    rev_result = await alice.revoke_key(reason=RevocationReason.KEY_COMPROMISE)
    assert_test("Alice's revocation succeeded on-chain", rev_result.get("success") is True)

    # Give relay time to deliver scoped packets
    await asyncio.sleep(1.5)

    # Count how many scoped packets Alice sent
    scoped_sent = alice.metrics["packets_sent_scoped"] - alice_metrics_before
    print(f"\n  📦 Packets Alice sent (Scoped):  {scoped_sent}")
    print(f"  📦 Old Broadcast would send:     {len(nodes) - 1} (O(N) = 3)")

    # Bob should have received 1 revocation packet (he's in #dev)
    bob_rev_packets = sniffer.revocation_packets.get(bob.peer_id, 0)
    charlie_rev_packets = sniffer.revocation_packets.get(charlie.peer_id, 0)
    dave_rev_packets = sniffer.revocation_packets.get(dave.peer_id, 0)

    print(f"\n  📬 Bob's revocation packets received:     {bob_rev_packets}")
    print(f"  📬 Charlie's revocation packets received: {charlie_rev_packets}")
    print(f"  📬 Dave's revocation packets received:    {dave_rev_packets}")
    print()

    assert_test(
        "Bob received scoped revocation alert",
        bob_rev_packets >= 1,
        f"Bob got {bob_rev_packets} revocation packet(s)"
    )
    assert_test(
        "Charlie received 0 revocation packets (congestion eliminated)",
        charlie_rev_packets == 0,
        "No spam to strangers"
    )
    assert_test(
        "Dave received 0 revocation packets (congestion eliminated)",
        dave_rev_packets == 0,
        "No spam to strangers"
    )
    assert_test(
        "Scoped delivery used fewer packets than broadcast",
        scoped_sent < (len(nodes) - 1),
        f"Scoped={scoped_sent} vs Broadcast={len(nodes) - 1}"
    )

    # Verify Bob's node processed the revocation correctly
    assert_test(
        "Bob's local chain marks Alice as REVOKED",
        alice.peer_id in bob.revoked_peers,
        f"Bob's revoked_peers contains Alice"
    )
    assert_test(
        "Bob's trust score for Alice dropped to 0",
        bob.trust_scores.get(alice.peer_id, -1) == 0,
        f"Trust = {bob.trust_scores.get(alice.peer_id)}"
    )

    # ════════════════════════════════════════════════════════════════════
    #  PHASE 2: On-Demand Lazy Verification Test
    # ════════════════════════════════════════════════════════════════════
    print()
    print("─" * 70)
    print("  PHASE 2: On-Demand Lazy Verification Test")
    print("─" * 70)
    print()

    # Charlie NEVER received a revocation broadcast packet (confirmed above).
    # Now Charlie decides to message Alice.
    print("  💬 Charlie attempts to send DM to Alice (who is revoked)...")
    print("     Charlie has received 0 revocation packets about Alice.")
    print("     Charlie must discover Alice's revocation through LAZY ON-DEMAND check.\n")

    # Manually register Alice's revocation on Charlie's local chain
    # (simulating that Charlie's chain has the same consensus state)
    await charlie.blockchain.revoke_key(
        alice.peer_id, RevocationReason.KEY_COMPROMISE, alice.private_key
    )

    charlie_cache_misses_before = charlie.metrics["cache_misses"]

    # Charlie tries to DM Alice — this triggers verify_peer_revocation_lazy()
    dm_result = await charlie.send_direct_message(alice.peer_id, "Hey Alice, are you there?")

    assert_test(
        "Charlie's DM to revoked Alice was BLOCKED",
        dm_result.get("success") is False,
        f"Error: {dm_result.get('error', 'N/A')}"
    )

    # Verify lazy check was triggered (cache miss → on-chain query)
    charlie_cache_misses_after = charlie.metrics["cache_misses"]
    assert_test(
        "Lazy verification triggered a cache miss (on-chain query)",
        charlie_cache_misses_after > charlie_cache_misses_before,
        f"Cache misses: {charlie_cache_misses_before} → {charlie_cache_misses_after}"
    )

    # Verify Alice is now in Charlie's revocation cache
    cached_entry = charlie.revocation_cache.get(alice.peer_id, {})
    assert_test(
        "Alice's revocation is now cached on Charlie's node",
        cached_entry.get("is_revoked") is True,
        f"Cached status: {cached_entry.get('status')}"
    )

    assert_test(
        "Charlie's trust for Alice is now 0",
        charlie.trust_scores.get(alice.peer_id, -1) == 0,
        "Security 100% preserved without broadcast"
    )

    # ════════════════════════════════════════════════════════════════════
    #  PHASE 3: Cache Performance Benchmark
    # ════════════════════════════════════════════════════════════════════
    print()
    print("─" * 70)
    print("  PHASE 3: Cache Performance Benchmark (TTL Hits)")
    print("─" * 70)
    print()

    cache_hits_before = charlie.metrics["cache_hits"]
    num_lookups = 1000
    t_start = time.perf_counter_ns()

    for _ in range(num_lookups):
        result = await charlie.verify_peer_revocation_lazy(alice.peer_id)
        assert result["is_revoked"] is True
        assert result["from_cache"] is True

    t_end = time.perf_counter_ns()
    elapsed_ms = (t_end - t_start) / 1_000_000
    avg_ns = (t_end - t_start) / num_lookups

    cache_hits_after = charlie.metrics["cache_hits"]
    new_hits = cache_hits_after - cache_hits_before

    print(f"  ⚡ {num_lookups} cached lookups completed in {elapsed_ms:.2f} ms")
    print(f"  ⚡ Average per lookup: {avg_ns:.0f} ns ({avg_ns / 1000:.2f} µs)")
    print(f"  ⚡ Cache hits: {new_hits}")
    print()

    assert_test(
        f"All {num_lookups} lookups served from cache",
        new_hits == num_lookups,
        f"Expected {num_lookups} hits, got {new_hits}"
    )
    assert_test(
        "Average lookup under 100µs (sub-millisecond)",
        avg_ns < 100_000,
        f"Avg = {avg_ns:.0f} ns = {avg_ns / 1000:.2f} µs"
    )

    # ════════════════════════════════════════════════════════════════════
    #  RESULTS SUMMARY
    # ════════════════════════════════════════════════════════════════════
    print()
    print("═" * 70)

    total = len(results)
    passed = sum(1 for _, ok in results if ok)
    failed = total - passed

    # Final metrics summary table
    print(f"\n  📊 REVOCATION EFFICIENCY METRICS SUMMARY")
    print(f"  {'─' * 50}")
    print(f"  │ Metric                         │ Value       │")
    print(f"  {'─' * 50}")
    print(f"  │ Scoped packets sent (Alice)     │ {scoped_sent:<12}│")
    print(f"  │ Broadcast would send (Old)      │ {len(nodes)-1:<12}│")
    print(f"  │ Bandwidth saved                 │ {((len(nodes)-1 - scoped_sent) / (len(nodes)-1) * 100):.0f}%{'':8}│")
    print(f"  │ Bob (contact) packets           │ {bob_rev_packets:<12}│")
    print(f"  │ Charlie (stranger) packets      │ {charlie_rev_packets:<12}│")
    print(f"  │ Dave (stranger) packets          │ {dave_rev_packets:<12}│")
    print(f"  │ Lazy cache lookups (1000x)      │ {elapsed_ms:.2f} ms{'':4}│")
    print(f"  │ Avg per lookup                  │ {avg_ns / 1000:.2f} µs{'':5}│")
    print(f"  {'─' * 50}")

    print()
    if failed == 0:
        print(f"  🎉 ALL {total} TESTS PASSED — SCOPED REVOCATION VERIFIED!")
    else:
        print(f"  ⚠️  {passed}/{total} tests passed, {failed} FAILED")
    print("═" * 70)

    # ── Cleanup ─────────────────────────────────────────────────────────
    for node in nodes:
        await node.stop()
    server.close()
    await server.wait_closed()

    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(run_benchmark())
    sys.exit(0 if success else 1)
