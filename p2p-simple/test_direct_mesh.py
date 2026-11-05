"""Real TCP regressions for discovery-only bootstrap and independent peers."""

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

import relay
from peer_node import PeerNode


async def wait_until(predicate, timeout=5.0):
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.02)


class DirectMeshTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.identities = tempfile.TemporaryDirectory()
        self.bootstrap_frames = []
        frames = self.bootstrap_frames

        class DiscoveryReader:
            def __init__(self, reader):
                self.reader = reader

            async def readline(self):
                line = await self.reader.readline()
                if line:
                    frames.append(json.loads(line))
                return line

        async def directory(reader, writer):
            await relay.handle_client(DiscoveryReader(reader), writer)

        self.server = await asyncio.start_server(directory, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        self.nodes = [
            PeerNode(peer_id=name, relay_port=self.port, listen_host="127.0.0.1",
                     identity_file=str(Path(self.identities.name, name + ".json")))
            for name in ("Mesh_A", "Mesh_B", "Mesh_C")
        ]
        self.a, self.b, self.c = self.nodes
        await asyncio.gather(*(node.start() for node in self.nodes))
        await self.wait_for_mesh()

    async def asyncTearDown(self):
        self.server.close()
        await asyncio.gather(*(node.stop() for node in self.nodes))
        for writer in list(relay.active_peers.values()):
            writer.close()
        await asyncio.wait_for(self.server.wait_closed(), 5)
        await wait_until(lambda: not relay.active_peers)
        self.identities.cleanup()

    async def wait_for_mesh(self):
        ids = {node.peer_id for node in self.nodes}
        await wait_until(lambda: all(
            node.connected_peers == ids - {node.peer_id}
            and ids - {node.peer_id} <= node.key_registry.keys()
            and node.channel_members.get("#general") == ids - {node.peer_id}
            for node in self.nodes
        ))
        # Let initial chain responses finish before testing mutations.
        await asyncio.sleep(0.1)

    async def stop_bootstrap(self):
        self.server.close()
        for writer in list(relay.active_peers.values()):
            writer.close()
        await asyncio.wait_for(self.server.wait_closed(), 5)
        await wait_until(lambda: all(node._relay_writer is None for node in self.nodes))

    async def assert_delivered(self, sender, receiver, text):
        result = await sender.send_direct_message(receiver.peer_id, text)
        self.assertTrue(result["success"], result)
        await wait_until(lambda: any(m["text"] == text for m in receiver.message_history))

    async def test_automatic_mesh_has_one_stable_connection_per_pair(self):
        before = {n.peer_id: dict(n._peer_writers) for n in self.nodes}
        await asyncio.sleep(0.7)
        for node in self.nodes:
            self.assertEqual(node._peer_writers, before[node.peer_id])
            for other in self.nodes:
                if other is not node:
                    self.assertEqual(node._peer_connection_ids[other.peer_id],
                                     other._peer_connection_ids[node.peer_id])
        await self.assert_delivered(self.a, self.b, "automatic mesh")

    async def test_bootstrap_never_carries_application_data_or_duplicates_broadcasts(self):
        await self.assert_delivered(self.a, self.b, "direct with bootstrap online")
        self.assertTrue((await self.a.send_broadcast("one broadcast"))["success"])
        self.assertTrue((await self.a.send_channel_message("#general", "one channel message"))["success"])
        for node in (self.b, self.c):
            await wait_until(lambda: any(m["text"] == "one channel message" for m in node.message_history))
            await wait_until(lambda: any(m["text"] == "one broadcast" for m in node.message_history))
        await asyncio.sleep(0.1)
        for node in (self.b, self.c):
            for text in ("one broadcast", "one channel message"):
                self.assertEqual(sum(m["text"] == text for m in node.message_history), 1)
        self.assertTrue(self.bootstrap_frames)
        self.assertEqual({f["type"] for f in self.bootstrap_frames}, {"REGISTER_PEER"})

    async def test_messages_receipts_and_key_lifecycle_survive_bootstrap_stop(self):
        writers = dict(self.a._peer_writers)
        members = set(self.a.channel_members["#general"])
        await self.stop_bootstrap()
        self.assertEqual(self.a._peer_writers, writers)
        self.assertEqual(self.a.channel_members["#general"], members)
        await self.assert_delivered(self.a, self.b, "DM after bootstrap stop")
        self.assertTrue((await self.a.send_channel_message("#general", "channel after stop"))["success"])
        self.assertTrue((await self.a.send_broadcast("broadcast after stop"))["success"])
        for node in (self.b, self.c):
            await wait_until(lambda: any(m["text"] == "channel after stop" for m in node.message_history))
            await wait_until(lambda: any(m["text"] == "broadcast after stop" for m in node.message_history))
        await wait_until(lambda: len(self.b.blockchain.get_message_receipts(self.a.peer_id)) >= 3)
        before = self.a.metrics["packets_sent_scoped"]
        self.assertTrue((await self.a.revoke_key())["success"])
        await wait_until(lambda: all(self.a.peer_id in n.revoked_peers for n in (self.b, self.c)))
        self.assertEqual(self.a.metrics["packets_sent_scoped"] - before, 2)
        verified = await self.b.verify_peer_revocation_lazy(self.a.peer_id, force_refresh=True)
        self.assertTrue(verified["is_revoked"], verified)
        self.assertFalse((await self.b.send_direct_message(self.a.peer_id, "blocked"))["success"])
        self.assertTrue((await self.a.unrevoke_key())["success"])
        await wait_until(lambda: all(self.a.peer_id not in n.revoked_peers for n in (self.b, self.c)))
        self.assertTrue((await self.a.rotate_key())["success"])
        await wait_until(lambda: all(n.key_registry.get(self.a.peer_id) == self.a.public_key for n in (self.b, self.c)))
        await self.assert_delivered(self.b, self.a, "DM after rotation")

    async def test_inflight_chain_refresh_survives_bootstrap_stop(self):
        entered, release = asyncio.Event(), asyncio.Event()
        dispatch = self.b._dispatch_protocol

        async def delayed(msg):
            if msg.get("data", {}).get("type") == "GET_CHAIN":
                entered.set()
                await release.wait()
            await dispatch(msg)

        self.b._dispatch_protocol = delayed
        refresh = asyncio.create_task(self.a.verify_peer_revocation_lazy(self.b.peer_id, force_refresh=True))
        try:
            await asyncio.wait_for(entered.wait(), 1)
            await self.stop_bootstrap()
            release.set()
            self.assertTrue((await refresh)["verified"])
        finally:
            release.set()
            if not refresh.done():
                refresh.cancel()
            await asyncio.gather(refresh, return_exceptions=True)

    async def test_scoped_revocation_and_stranger_refresh_without_bootstrap(self):
        await self.c.join_channel("#marketing")
        await self.c.leave_channel("#general")
        await wait_until(lambda: all(self.c.peer_id not in n.get_active_contacts() for n in (self.a, self.b)))
        await self.stop_bootstrap()
        self.assertTrue((await self.a.revoke_key())["success"])
        await wait_until(lambda: self.a.peer_id in self.b.revoked_peers)
        self.assertEqual(self.a.metrics["packets_sent_scoped"], 1)
        self.assertEqual(self.c.metrics["packets_received_revocation"], 0)
        status = await self.c.verify_peer_revocation_lazy(self.a.peer_id, force_refresh=True)
        self.assertTrue(status["is_revoked"], status)

    async def test_direct_connection_recovers_without_bootstrap(self):
        await self.stop_bootstrap()
        old = self.a._peer_writers[self.b.peer_id]
        old.close()
        await wait_until(lambda: self.a._peer_writers.get(self.b.peer_id) not in (None, old))
        await self.wait_for_mesh()
        await self.assert_delivered(self.a, self.b, "after direct reconnect")

    async def test_new_peer_joins_through_existing_peer_without_bootstrap(self):
        await self.stop_bootstrap()
        newcomer = PeerNode(peer_id="Mesh_D", relay_host=None, listen_host="127.0.0.1",
                            seed_peers=[("127.0.0.1", self.a.listen_port)])
        self.nodes.append(newcomer)
        self.assertTrue(await newcomer.start())
        await self.wait_for_mesh()
        self.assertIsNone(newcomer._relay_writer)
        await self.assert_delivered(newcomer, self.c, "joined through peer exchange")

    async def test_restarted_peer_rejoins_through_seed_without_bootstrap(self):
        await self.stop_bootstrap()
        await self.c.stop()
        self.nodes.remove(self.c)
        await wait_until(lambda: self.c.peer_id not in self.a.connected_peers)
        replacement = PeerNode(identity_file=self.c.identity_file, relay_host=None,
                               listen_host="127.0.0.1",
                               seed_peers=[("127.0.0.1", self.a.listen_port)])
        self.nodes.append(replacement)
        self.assertTrue(await replacement.start())
        await self.wait_for_mesh()
        await self.assert_delivered(self.a, replacement, "after peer restart")

    async def test_missing_direct_connection_cannot_refresh_active_cache(self):
        await self.a.verify_peer_revocation_lazy(self.b.peer_id)
        await self.stop_bootstrap()
        await self.b.stop()
        await wait_until(lambda: self.b.peer_id not in self.a.connected_peers)
        status = await self.a.verify_peer_revocation_lazy(self.b.peer_id, force_refresh=True)
        self.assertFalse(status["verified"])
        self.assertEqual(status["status"], "SYNC_UNAVAILABLE")
        self.assertNotIn(self.b.peer_id, self.a.revocation_cache)


class BootstrapDirectoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_directory_returns_addresses_but_refuses_message_forwarding(self):
        server = await asyncio.start_server(relay.handle_client, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        writers = []
        try:
            peers = []
            for pid, listen_port in (("Directory_A", 65001), ("Directory_B", 65002)):
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writers.append(writer)
                writer.write((json.dumps({"type": "REGISTER_PEER", "peerId": pid,
                                         "listenHost": "127.0.0.1", "listenPort": listen_port}) + "\n").encode())
                await writer.drain()
                peers.append((reader, writer, json.loads(await asyncio.wait_for(reader.readline(), 1))))
            ra, wa, _ = peers[0]
            rb, _, listing = peers[1]
            self.assertEqual(listing["peers"], [{
                "peerId": "Directory_A", "listenHost": "127.0.0.1", "listenPort": 65001,
            }])
            self.assertEqual(json.loads(await asyncio.wait_for(ra.readline(), 1))["type"], "PEER_JOINED")
            wa.write((json.dumps({"type": "ROUTED_MSG", "target": "*",
                                 "protocol": "/chat/1.0.0", "data": {"message": "must not forward"}}) + "\n").encode())
            await wa.drain()
            self.assertEqual(json.loads(await asyncio.wait_for(ra.readline(), 1))["type"], "ERROR")
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(rb.readline(), 0.15)
        finally:
            server.close()
            for writer in writers:
                writer.close()
                await writer.wait_closed()
            await asyncio.wait_for(server.wait_closed(), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
