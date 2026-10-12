"""Regressions for stale revocation caches and authenticated messaging."""

import asyncio
import time
import unittest
from unittest.mock import patch

from blockchain import Block, Transaction, TransactionType
from peer_node import PeerNode
import relay


class RevocationRegressions(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.alice = PeerNode(peer_id="Alice", auto_register_blockchain=False)
        self.bob = PeerNode(peer_id="Bob", auto_register_blockchain=False)
        for node in (self.alice, self.bob):
            for owner in (self.alice, self.bob):
                await node.blockchain.register_key(
                    owner.peer_id, owner.public_key, owner.did["id"], owner.private_key
                )

    async def test_scoped_revocation_overrides_fresh_active_cache(self):
        await self.bob.verify_peer_revocation_lazy("Alice")
        result = await self.alice.revoke_key()
        await self.bob._dispatch_protocol({
            "protocol": "/chain/tx/1.0.0", "sender": "Alice",
            "data": result["transaction"].to_dict(),
        })
        status = await self.bob.verify_peer_revocation_lazy("Alice")
        self.assertTrue(status["is_revoked"])
        self.assertEqual(self.bob.trust_scores["Alice"], 0)

    async def test_blockchain_events_update_cached_reinstatement(self):
        await self.bob.blockchain.revoke_key("Alice", 1, self.alice.private_key)
        await self.bob.verify_peer_revocation_lazy("Alice")
        await self.bob.blockchain.unrevoke_key("Alice", self.alice.private_key)
        status = await self.bob.verify_peer_revocation_lazy("Alice")
        self.assertFalse(status["is_revoked"])
        self.assertNotIn("Alice", self.bob.revoked_peers)
        self.assertEqual(self.bob.trust_scores["Alice"], 50)

    async def test_chain_replacement_updates_node_three_cache(self):
        charlie = PeerNode(peer_id="Charlie", auto_register_blockchain=False)
        await self.alice.revoke_key()
        charlie.blockchain.replace_chain(self.alice.get_blockchain_history())
        await charlie.verify_peer_revocation_lazy("Alice")
        await self.alice.unrevoke_key()
        await charlie._dispatch_protocol({
            "protocol": "/chain/sync/1.0.0", "sender": "Alice",
            "data": {"type": "CHAIN_RESPONSE", "chain": self.alice.get_blockchain_history()},
        })
        status = await charlie.verify_peer_revocation_lazy("Alice")
        self.assertFalse(status["is_revoked"])
        self.assertNotIn("Alice", charlie.revoked_peers)
        self.assertEqual(charlie.trust_scores["Alice"], 50)

    async def test_entry_ttl_is_not_extended_by_default_argument(self):
        await self.bob.verify_peer_revocation_lazy("Alice", ttl=1.0)
        cached_at = self.bob.revocation_cache["Alice"]["cached_at"]
        with patch("peer_node.time.time", return_value=cached_at + 2.0):
            result = await self.bob.verify_peer_revocation_lazy("Alice")
        self.assertFalse(result["from_cache"])

    async def test_invalid_revocation_cannot_quarantine_peer(self):
        forged = Transaction(type=TransactionType.REVOKE_KEY,
                             senderPeerId="Alice", payload={"reason": 1})
        forged.sign(self.bob.private_key)
        await self.bob._dispatch_protocol({
            "protocol": "/chain/tx/1.0.0", "sender": "Alice", "data": forged.to_dict(),
        })
        self.assertNotIn("Alice", self.bob.revoked_peers)
        self.assertFalse(self.bob.blockchain.state["Alice"]["isRevoked"])
        self.assertEqual(self.bob.metrics["packets_received_revocation"], 0)

    async def test_unsigned_channel_message_is_rejected(self):
        encrypted = self.alice.crypto_suite.encrypt_channel(
            "Forged channel message", self.alice.get_channel_key("#general")
        )
        await self.bob._dispatch_protocol({
            "protocol": "/chat/channel/1.0.0", "sender": "Alice",
            "data": {"channel": "#general", "from": "Alice",
                     "encryptedData": encrypted, "timestamp": int(time.time() * 1000)},
        })
        self.assertFalse(self.bob.message_history)

    async def test_unsigned_broadcast_is_rejected(self):
        await self.bob._dispatch_protocol({
            "protocol": "/chat/1.0.0", "sender": "Alice",
            "data": {"from": "Alice", "message": "Forged broadcast"},
        })
        self.assertFalse(self.bob.message_history)

    async def test_revoked_node_cannot_send_channel_or_broadcast(self):
        await self.alice.revoke_key()
        channel = await self.alice.send_channel_message("#general", "Blocked")
        broadcast = await self.alice.send_broadcast("Blocked")
        self.assertFalse(channel["success"])
        self.assertFalse(broadcast["success"])
        self.assertFalse(self.alice.message_history)

    async def test_default_channel_can_be_left_for_scoped_groups(self):
        await self.bob.join_channel("#marketing")
        await self.bob.leave_channel("#general")
        self.assertNotIn("#general", self.bob.joined_channels)
        self.assertEqual(self.bob.active_channel, "#marketing")

    async def test_leaving_channel_removes_channel_only_contacts(self):
        self.bob.channel_members["#general"].add("Alice")
        self.bob._record_message("INCOMING_CHANNEL", "Alice", "#general", "Hello", "Channel")
        await self.bob.join_channel("#marketing")
        await self.bob.leave_channel("#general")
        self.assertNotIn("Alice", self.bob.get_active_contacts())

    async def test_chain_with_forged_revocation_is_rejected(self):
        chain_data = self.alice.get_blockchain_history()
        forged = Transaction(type=TransactionType.REVOKE_KEY,
                             senderPeerId="Alice", payload={"reason": 1})
        forged.sign(self.bob.private_key)
        block = Block(index=len(chain_data), timestamp=int(time.time() * 1000),
                      previousHash=chain_data[-1]["hash"], transactions=[forged])
        block.mine(self.bob.blockchain.difficulty)
        chain_data.append(block.to_dict())
        self.assertFalse(self.bob.blockchain.replace_chain(chain_data))
        self.assertFalse(self.bob.blockchain.state["Alice"]["isRevoked"])

    async def test_duplicate_transaction_does_not_replay_events(self):
        result = await self.alice.revoke_key()
        height = len(self.alice.blockchain.chain)
        repeated = self.alice.blockchain.add_transaction(result["transaction"])
        self.assertTrue(repeated["success"])
        self.assertEqual(len(self.alice.blockchain.chain), height)

    async def test_state_resync_does_not_extend_unchanged_cache_ttl(self):
        await self.bob.verify_peer_revocation_lazy("Alice", ttl=30.0)
        cached_at = self.bob.revocation_cache["Alice"]["cached_at"]
        with patch("peer_node.time.time", return_value=cached_at + 10.0):
            self.bob._resync_state_from_chain()
        self.assertEqual(self.bob.revocation_cache["Alice"]["cached_at"], cached_at)

    async def test_unsigned_data_cannot_extend_chain(self):
        height = len(self.alice.blockchain.chain)
        tx = Transaction(type=TransactionType.DATA, senderPeerId="Alice", payload={"test": 1})
        self.assertFalse(self.alice.blockchain.add_transaction(tx)["success"])
        self.assertEqual(len(self.alice.blockchain.chain), height)


async def wait_until(predicate, timeout=3.0):
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.01)


class ThreeNodeNetworkRegressions(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        relay.active_peers.clear()
        self.server = await asyncio.start_server(relay.handle_client, "127.0.0.1", 0)
        port = self.server.sockets[0].getsockname()[1]
        self.alice = PeerNode(peer_id="Alice_Live", relay_port=port)
        self.bob = PeerNode(peer_id="Bob_Live", relay_port=port)
        self.charlie = PeerNode(peer_id="Charlie_Live", relay_port=port)
        self.nodes = (self.alice, self.bob, self.charlie)
        for node in self.nodes:
            await node.join_channel("#dev" if node != self.charlie else "#marketing")
            await node.leave_channel("#general")
            self.assertTrue(await node.start())
        await wait_until(lambda: all(len(n.connected_peers) == 2 and
                                    all(p.peer_id in n.blockchain.state for p in self.nodes)
                                    for n in self.nodes))
        await wait_until(lambda: self.alice.peer_id in self.bob.get_active_contacts()
                         and self.bob.peer_id in self.alice.get_active_contacts())
        await asyncio.sleep(0.3)

    async def asyncTearDown(self):
        for node in self.nodes:
            await node.stop()
        self.server.close()
        await self.server.wait_closed()
        await wait_until(lambda: not relay.active_peers)

    async def test_stranger_discovers_revocation_and_then_reinstatement(self):
        self.assertNotIn(self.charlie.peer_id, self.alice.get_active_contacts())
        result = await self.alice.revoke_key()
        self.assertTrue(result["success"])
        await wait_until(lambda: self.alice.peer_id in self.bob.revoked_peers)
        self.assertEqual(self.charlie.metrics["packets_received_revocation"], 0)
        self.assertEqual(self.alice.metrics["packets_sent_scoped"], 1)
        blocked = await self.charlie.send_direct_message(self.alice.peer_id, "Must be blocked")
        self.assertFalse(blocked["success"])
        self.assertIn(self.alice.peer_id, self.charlie.revoked_peers)
        self.assertEqual(self.charlie.trust_scores[self.alice.peer_id], 0)
        self.assertTrue((await self.alice.unrevoke_key())["success"])
        resumed = await self.charlie.send_direct_message(self.alice.peer_id, "Back after reinstatement")
        self.assertTrue(resumed["success"], resumed)
        await wait_until(lambda: any(m["text"] == "Back after reinstatement"
                                    for m in self.alice.message_history))
        self.assertNotIn(self.alice.peer_id, self.charlie.revoked_peers)
        hits_before = self.charlie.metrics["cache_hits"]
        self.assertTrue((await self.charlie.verify_peer_revocation_lazy(self.alice.peer_id))["from_cache"])
        self.assertEqual(self.charlie.metrics["cache_hits"], hits_before + 1)

    async def test_delayed_response_is_awaited_and_concurrent_requests_share_it(self):
        dispatch = self.alice._dispatch_protocol

        async def delayed(msg):
            if msg.get("data", {}).get("type") == "GET_CHAIN" and msg["data"].get("requestId"):
                await asyncio.sleep(0.75)
            await dispatch(msg)

        self.alice._dispatch_protocol = delayed
        before = self.charlie.metrics.get("chain_syncs_on_demand", 0)
        started = time.monotonic()
        results = await asyncio.gather(*[
            self.charlie.verify_peer_revocation_lazy(self.alice.peer_id, force_refresh=True)
            for _ in range(2)
        ])
        self.assertGreaterEqual(time.monotonic() - started, 0.70)
        self.assertTrue(all(r["verified"] for r in results), results)
        self.assertEqual(self.charlie.metrics["chain_syncs_on_demand"], before + 1)

    async def test_network_timeout_cannot_refresh_active_cache(self):
        await self.charlie.verify_peer_revocation_lazy(self.alice.peer_id)
        self.charlie.chain_sync_timeout = 0.1
        dispatch = self.alice._dispatch_protocol

        async def drop_reply(msg):
            if msg.get("data", {}).get("type") != "GET_CHAIN":
                await dispatch(msg)

        self.alice._dispatch_protocol = drop_reply
        result = await self.charlie.verify_peer_revocation_lazy(self.alice.peer_id, force_refresh=True)
        self.assertFalse(result["verified"])
        self.assertEqual(result["status"], "SYNC_UNAVAILABLE")
        self.assertNotIn(self.alice.peer_id, self.charlie.revocation_cache)
        self.assertFalse((await self.charlie.send_direct_message(self.alice.peer_id, "No fresh proof"))["success"])

    async def test_newer_revocation_in_shorter_chain_is_discovered(self):
        for index in range(4):
            tx = Transaction(type=TransactionType.DATA, senderPeerId=self.charlie.peer_id,
                             payload={"test": index})
            tx.sign(self.charlie.private_key)
            self.charlie.blockchain.add_transaction(tx)
        await self.alice.revoke_key()
        self.assertGreater(len(self.charlie.blockchain.chain), len(self.alice.blockchain.chain))
        result = await self.charlie.send_direct_message(self.alice.peer_id, "Must be blocked")
        self.assertFalse(result["success"])
        self.assertIn(self.alice.peer_id, self.charlie.revoked_peers)

    async def test_incoming_verification_does_not_block_relay_responses(self):
        self.bob.revocation_cache.clear()
        received = asyncio.Event()
        self.bob.on_message_received = lambda message: received.set()
        result = await self.alice.send_direct_message(self.bob.peer_id, "Verified by a live receiver")
        self.assertTrue(result["success"], result)
        await asyncio.wait_for(received.wait(), timeout=1.0)
        self.assertEqual(self.bob.message_history[-1]["text"], "Verified by a live receiver")
        self.assertGreater(self.bob.metrics.get("chain_syncs_on_demand", 0), 0)

    async def test_relay_reconnect_rebuilds_memberships_and_clears_cache(self):
        await self.charlie.verify_peer_revocation_lazy(self.alice.peer_id)
        events = []
        self.charlie.on_peer_event = lambda event, pid: events.append(event)
        relay.active_peers[self.charlie.peer_id].close()
        await wait_until(lambda: "RELAY_DISCONNECTED" in events)
        self.assertFalse(self.charlie.revocation_cache)
        await wait_until(lambda: "RELAY_CONNECTED" in events)
        await wait_until(lambda: len(self.charlie.connected_peers) == 2)
        result = await self.charlie.verify_peer_revocation_lazy(self.alice.peer_id)
        self.assertTrue(result["verified"], result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
