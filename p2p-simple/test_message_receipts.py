#!/usr/bin/env python3
"""
Test Suite: On-Chain Message Receipts & Notarization (Option A)
Verifies:
1. NativeBlockchain commit_message_receipt, get_message_receipts, and verify_message_receipt
2. Automatic receipt anchoring on PeerNode for Direct Messages, Channels, and Broadcasts
3. Wire delivery and receiver message_history verification
"""

import asyncio
import os
import sys
import unittest

from crypto import generate_key_pair, sha256
from blockchain import NativeBlockchain, TransactionType
from peer_node import PeerNode
import relay

class MessageReceiptTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = await asyncio.start_server(relay.handle_client, "127.0.0.1", 4125)

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        for f in ["test_id_node1.json", "test_id_node2.json"]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

    async def test_blockchain_message_receipt_anchoring(self):
        bc = NativeBlockchain(difficulty=1)
        # Register a key first
        kp = generate_key_pair()
        reg_res = await bc.register_key("peer_alice", kp["publicKey"], "did:peer:peer_alice", kp["privateKey"])
        self.assertTrue(reg_res["success"])
        self.assertEqual(len(bc.chain), 2)

        # Commit message receipt for DM
        msg_hash = sha256("Secret payload between Alice and Bob")
        res = await bc.commit_message_receipt("peer_alice", "peer_bob", msg_hash, kp["privateKey"], msg_type="DM")
        self.assertTrue(res["success"])
        self.assertEqual(len(bc.chain), 3)

        # Commit message receipt for Channel
        ch_hash = sha256("Channel announcement")
        res_ch = await bc.commit_message_receipt("peer_alice", "#secops", ch_hash, kp["privateKey"], msg_type="CHANNEL")
        self.assertTrue(res_ch["success"])
        self.assertEqual(len(bc.chain), 4)

        # Commit message receipt for Broadcast
        bcast_hash = sha256("Emergency bulletin")
        res_bc = await bc.commit_message_receipt("peer_alice", "*", bcast_hash, kp["privateKey"], msg_type="BROADCAST")
        self.assertTrue(res_bc["success"])
        self.assertEqual(len(bc.chain), 5)

        # Verify receipt lookup
        receipts = bc.get_message_receipts()
        self.assertEqual(len(receipts), 3)

        self.assertEqual(receipts[0]["msgType"], "DM")
        self.assertEqual(receipts[0]["recipient"], "peer_bob")
        self.assertEqual(receipts[0]["messageHash"], msg_hash)

        self.assertEqual(receipts[1]["msgType"], "CHANNEL")
        self.assertEqual(receipts[1]["target"], "#secops")
        self.assertEqual(receipts[1]["messageHash"], ch_hash)

        self.assertEqual(receipts[2]["msgType"], "BROADCAST")
        self.assertEqual(receipts[2]["target"], "*")
        self.assertEqual(receipts[2]["messageHash"], bcast_hash)

        # Verify cryptographic verification
        ver = bc.verify_message_receipt(ch_hash)
        self.assertIsNotNone(ver)
        self.assertTrue(ver["verified"])
        self.assertEqual(ver["msgType"], "CHANNEL")
        self.assertEqual(ver["target"], "#secops")

        # Non-existent hash
        self.assertIsNone(bc.verify_message_receipt("bogus_hash_12345"))

    async def test_node_anchored_dm_channel_and_broadcast(self):
        node1 = PeerNode("12D3KooWNode1", relay_host="127.0.0.1", relay_port=4125, identity_file="test_id_node1.json")
        node2 = PeerNode("12D3KooWNode2", relay_host="127.0.0.1", relay_port=4125, identity_file="test_id_node2.json")
        await node1.start()
        await node2.start()
        await asyncio.sleep(0.5)

        received_msgs = []
        node2.on_message_received = lambda m: received_msgs.append(m)

        # 1. Automatic Anchored DM
        dm_text = "Mission coordinates: 48.8584, 2.2945"
        res_dm = await node1.send_direct_message(node2.peer_id, dm_text)
        self.assertTrue(res_dm["success"])
        self.assertIsNotNone(res_dm.get("receipt"))
        self.assertEqual(res_dm["receipt"]["msgType"], "DM")
        self.assertIn("messageHash", res_dm["receipt"])

        # 2. Join Channel and Send Automatic Anchored Channel Message
        await node1.join_channel("#intel")
        await node2.join_channel("#intel")
        await asyncio.sleep(0.3)

        ch_text = "Encrypted channel alert: Sector 7 clear"
        res_ch = await node1.send_channel_message("#intel", ch_text)
        self.assertTrue(res_ch["success"])
        self.assertIsNotNone(res_ch.get("receipt"))
        self.assertEqual(res_ch["receipt"]["msgType"], "CHANNEL")
        self.assertEqual(res_ch["receipt"]["target"], "#intel")

        # 3. Automatic Anchored Broadcast
        bcast_text = "Signed public broadcast to all peers"
        res_bc = await node1.send_broadcast(bcast_text)
        self.assertTrue(res_bc["success"])
        self.assertIsNotNone(res_bc.get("receipt"))
        self.assertEqual(res_bc["receipt"]["msgType"], "BROADCAST")
        self.assertEqual(res_bc["receipt"]["target"], "*")

        # Verify all 3 receipts stored in node1 blockchain
        receipts_node1 = node1.blockchain.get_message_receipts()
        self.assertEqual(len(receipts_node1), 3)

        await asyncio.sleep(0.5)

        # Verify node2 received all 3 messages with receipt attached
        self.assertEqual(len(received_msgs), 3)
        self.assertEqual(received_msgs[0]["kind"], "INCOMING_DM")
        self.assertEqual(received_msgs[0]["text"], dm_text)
        self.assertIsNotNone(received_msgs[0].get("receipt"))

        self.assertEqual(received_msgs[1]["kind"], "INCOMING_CHANNEL")
        self.assertEqual(received_msgs[1]["text"], ch_text)
        self.assertIsNotNone(received_msgs[1].get("receipt"))
        self.assertEqual(received_msgs[1]["receipt"]["target"], "#intel")

        self.assertEqual(received_msgs[2]["kind"], "INCOMING_BROADCAST")
        self.assertEqual(received_msgs[2]["text"], bcast_text)
        self.assertIsNotNone(received_msgs[2].get("receipt"))
        self.assertEqual(received_msgs[2]["receipt"]["target"], "*")

        await node1.stop()
        await node2.stop()

if __name__ == "__main__":
    unittest.main()
