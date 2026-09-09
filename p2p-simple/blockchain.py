import json
import random
import string
import time
from typing import Dict, Any, List, Optional, Union

from crypto import sha256, sign_message, verify_message


class RevocationReason:
    NONE = 0
    KEY_COMPROMISE = 1
    SUPERSEDED = 2
    DECOMMISSIONED = 3
    MALICIOUS_ACTIVITY = 4


class TransactionType:
    REGISTER_KEY = "REGISTER_KEY"
    REVOKE_KEY = "REVOKE_KEY"
    UNREVOKE_KEY = "UNREVOKE_KEY"
    ROTATE_KEY = "ROTATE_KEY"
    DATA = "DATA"


class Transaction:
    """
    Cryptographically signed Transaction in the native P2P blockchain.
    """
    def __init__(
        self,
        type: str,
        senderPeerId: str,
        payload: Optional[Dict[str, Any]] = None,
        nonce: Optional[str] = None,
        timestamp: Optional[int] = None,
        signature: Optional[str] = None,
        **kwargs
    ):
        self.type = type
        self.senderPeerId = senderPeerId
        self.payload = payload if payload is not None else {}
        self.nonce = nonce or "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        self.timestamp = timestamp or int(time.time() * 1000)
        self.signature = signature

    @classmethod
    def from_dict(cls, data: Union["Transaction", Dict[str, Any]]) -> "Transaction":
        if isinstance(data, cls):
            return data
        return cls(
            type=data.get("type"),
            senderPeerId=data.get("senderPeerId"),
            payload=data.get("payload", {}),
            nonce=data.get("nonce"),
            timestamp=data.get("timestamp"),
            signature=data.get("signature")
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "senderPeerId": self.senderPeerId,
            "payload": self.payload,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "signature": self.signature
        }

    def calculate_hash(self) -> str:
        """
        Deterministic SHA-256 hash of the transaction body.
        """
        body = {
            "type": self.type,
            "senderPeerId": self.senderPeerId,
            "payload": self.payload,
            "nonce": self.nonce,
            "timestamp": self.timestamp
        }
        serialized = json.dumps(body, separators=(",", ":"))
        return sha256(serialized)

    calculateHash = calculate_hash

    def sign(self, private_key_hex: str) -> str:
        """
        Sign transaction hash using sender's private key.
        """
        tx_hash = self.calculate_hash()
        self.signature = sign_message(tx_hash, private_key_hex)
        return self.signature

    def verify(self, public_key_hex: str) -> bool:
        """
        Verify signature against a public key.
        """
        if not self.signature:
            return False
        tx_hash = self.calculate_hash()
        return verify_message(tx_hash, self.signature, public_key_hex)


class Block:
    """
    Cryptographic Block containing an array of transactions.
    """
    def __init__(
        self,
        index: int,
        timestamp: Optional[int] = None,
        transactions: Optional[List[Union[Transaction, Dict[str, Any]]]] = None,
        previousHash: str = "",
        nonce: int = 0,
        hash: str = "",
        **kwargs
    ):
        self.index = index
        self.timestamp = timestamp or int(time.time() * 1000)
        self.transactions: List[Transaction] = [
            tx if isinstance(tx, Transaction) else Transaction.from_dict(tx)
            for tx in (transactions or [])
        ]
        self.previousHash = previousHash
        self.nonce = nonce
        self.hash = hash or self.calculate_hash()

    @classmethod
    def from_dict(cls, data: Union["Block", Dict[str, Any]]) -> "Block":
        if isinstance(data, cls):
            return data
        return cls(
            index=data["index"],
            timestamp=data.get("timestamp"),
            transactions=data.get("transactions", []),
            previousHash=data.get("previousHash", ""),
            nonce=data.get("nonce", 0),
            hash=data.get("hash", "")
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previousHash": self.previousHash,
            "nonce": self.nonce,
            "hash": self.hash
        }

    def calculate_hash(self) -> str:
        """
        Calculate SHA-256 hash of block contents.
        """
        tx_hashes = ":".join(tx.calculate_hash() for tx in self.transactions)
        content = f"{self.index}|{self.timestamp}|{self.previousHash}|{tx_hashes}|{self.nonce}"
        return sha256(content)

    calculateHash = calculate_hash

    def mine(self, difficulty: int = 1) -> str:
        """
        Fast Proof-of-Work mining for tamper-evidence.
        """
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()
        return self.hash


class NativeBlockchain:
    """
    Native In-Code P2P Blockchain & Decentralized PKI Engine.
    """
    def __init__(self, difficulty: int = 1, **kwargs):
        self.difficulty = difficulty
        self.chain: List[Block] = [self.create_genesis_block()]
        self.mempool: List[Transaction] = []
        self.state: Dict[str, Dict[str, Any]] = {}  # peerId -> IdentityRecord
        self.key_histories: Dict[str, List[str]] = {}  # peerId -> list of public keys
        self.listeners: Dict[str, List[Any]] = {
            "onKeyRegistered": [],
            "onKeyRevoked": [],
            "onKeyUnrevoked": [],
            "onKeyRotated": [],
            "onBlockAdded": []
        }
        self.isOnline = True

    def create_genesis_block(self) -> Block:
        """
        Create immutable Genesis block.
        """
        return Block(
            index=0,
            timestamp=1700000000000,
            transactions=[],
            previousHash="0000000000000000000000000000000000000000000000000000000000000000",
            nonce=0,
            hash="0000000000genesis_block_hash_native_p2p_chain_00000000000000000000"
        )

    createGenesisBlock = create_genesis_block

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    getLatestBlock = get_latest_block

    def validate_transaction(self, tx: Union[Transaction, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate a single transaction against current state.
        """
        tx_obj = tx if isinstance(tx, Transaction) else Transaction.from_dict(tx)
        if not tx_obj or not tx_obj.senderPeerId or not tx_obj.type:
            return {"valid": False, "error": "Malformed transaction"}

        record = self.state.get(tx_obj.senderPeerId)

        if tx_obj.type == TransactionType.REGISTER_KEY:
            payload = tx_obj.payload or {}
            pub_hex = payload.get("publicKeyHex")
            did_uri = payload.get("didUri")
            if not pub_hex or not did_uri:
                return {"valid": False, "error": "Missing public key or DID in payload"}

            if not record:
                ok = tx_obj.verify(pub_hex)
                return {"valid": True} if ok else {"valid": False, "error": "Invalid initial registration signature"}
            else:
                if record.get("isRevoked"):
                    return {"valid": False, "error": "Key is revoked. Cannot register with same peer ID."}
                ok = tx_obj.verify(record["publicKeyHex"])
                return {"valid": True} if ok else {"valid": False, "error": "Invalid signature from registered key"}

        if tx_obj.type == TransactionType.REVOKE_KEY:
            if not record:
                return {"valid": False, "error": "Identity not registered"}
            if record.get("isRevoked"):
                return {"valid": False, "error": "Identity already revoked"}
            ok = tx_obj.verify(record["publicKeyHex"])
            return {"valid": True} if ok else {"valid": False, "error": "Invalid signature on revocation"}

        if tx_obj.type == TransactionType.UNREVOKE_KEY:
            if not record:
                return {"valid": False, "error": "Identity not registered"}
            if not record.get("isRevoked"):
                return {"valid": False, "error": "Identity is not revoked"}
            ok = tx_obj.verify(record["publicKeyHex"])
            return {"valid": True} if ok else {"valid": False, "error": "Invalid signature on unrevocation"}

        if tx_obj.type == TransactionType.ROTATE_KEY:
            if not record:
                return {"valid": False, "error": "Identity not registered"}
            if record.get("isRevoked"):
                return {"valid": False, "error": "Cannot rotate a revoked key"}
            payload = tx_obj.payload or {}
            new_pub = payload.get("newPublicKeyHex")
            new_did = payload.get("newDidUri")
            if not new_pub or not new_did:
                return {"valid": False, "error": "Missing new key or DID"}
            ok = tx_obj.verify(record["publicKeyHex"])
            return {"valid": True} if ok else {"valid": False, "error": "Invalid signature for key rotation"}

        return {"valid": True}

    validateTransaction = validate_transaction

    def apply_transaction_to_state(self, tx: Union[Transaction, Dict[str, Any]]) -> None:
        """
        Apply transaction changes to state.
        """
        tx_obj = tx if isinstance(tx, Transaction) else Transaction.from_dict(tx)
        tx_type = tx_obj.type
        sender = tx_obj.senderPeerId
        payload = tx_obj.payload
        timestamp = tx_obj.timestamp

        if tx_type == TransactionType.REGISTER_KEY:
            existing = self.state.get(sender)
            if not existing:
                self.state[sender] = {
                    "peerId": sender,
                    "publicKeyHex": payload.get("publicKeyHex"),
                    "didUri": payload.get("didUri"),
                    "isRevoked": False,
                    "reason": RevocationReason.NONE,
                    "createdAt": timestamp,
                    "updatedAt": timestamp,
                    "revokedAt": 0
                }
                history = self.key_histories.setdefault(sender, [])
                history.append(payload.get("publicKeyHex"))

                self.emit("onKeyRegistered", {
                    "peerId": sender,
                    "publicKeyHex": payload.get("publicKeyHex"),
                    "didUri": payload.get("didUri"),
                    "timestamp": timestamp
                })
            else:
                old_key = existing["publicKeyHex"]
                existing["publicKeyHex"] = payload.get("publicKeyHex")
                existing["didUri"] = payload.get("didUri")
                existing["updatedAt"] = timestamp
                history = self.key_histories.setdefault(sender, [])
                history.append(payload.get("publicKeyHex"))

                self.emit("onKeyRotated", {
                    "peerId": sender,
                    "oldKey": old_key,
                    "newKey": payload.get("publicKeyHex"),
                    "timestamp": timestamp
                })

        elif tx_type == TransactionType.REVOKE_KEY:
            record = self.state.get(sender)
            if record:
                record["isRevoked"] = True
                record["reason"] = payload.get("reason", RevocationReason.KEY_COMPROMISE)
                record["revokedAt"] = timestamp
                record["updatedAt"] = timestamp

                self.emit("onKeyRevoked", {
                    "peerId": sender,
                    "reason": record["reason"],
                    "timestamp": timestamp
                })

        elif tx_type == TransactionType.UNREVOKE_KEY:
            record = self.state.get(sender)
            if record:
                record["isRevoked"] = False
                record["reason"] = RevocationReason.NONE
                record["revokedAt"] = 0
                record["updatedAt"] = timestamp

                self.emit("onKeyUnrevoked", {
                    "peerId": sender,
                    "timestamp": timestamp
                })

        elif tx_type == TransactionType.ROTATE_KEY:
            record = self.state.get(sender)
            if record:
                old_key = record["publicKeyHex"]
                record["publicKeyHex"] = payload.get("newPublicKeyHex")
                record["didUri"] = payload.get("newDidUri")
                record["updatedAt"] = timestamp
                history = self.key_histories.setdefault(sender, [])
                history.append(payload.get("newPublicKeyHex"))

                self.emit("onKeyRotated", {
                    "peerId": sender,
                    "oldKey": old_key,
                    "newKey": payload.get("newPublicKeyHex"),
                    "timestamp": timestamp
                })

    applyTransactionToState = apply_transaction_to_state

    def add_transaction(self, tx: Union[Transaction, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Submit transaction to mempool and immediately produce a block.
        """
        tx_obj = tx if isinstance(tx, Transaction) else Transaction.from_dict(tx)
        check = self.validate_transaction(tx_obj)
        if not check.get("valid"):
            return {"success": False, "error": check.get("error")}

        self.mempool.append(tx_obj)
        block = self.mine_pending_transactions()
        return {
            "success": True,
            "txHash": tx_obj.calculate_hash(),
            "block": block,
            "transaction": tx_obj
        }

    addTransaction = add_transaction

    def mine_pending_transactions(self) -> Optional[Block]:
        """
        Mine a block from pending transactions in mempool.
        """
        if not self.mempool:
            return None

        previous_block = self.get_latest_block()
        block = Block(
            index=previous_block.index + 1,
            timestamp=int(time.time() * 1000),
            transactions=list(self.mempool),
            previousHash=previous_block.hash
        )

        block.mine(self.difficulty)
        self.chain.append(block)
        self.mempool = []

        for tx in block.transactions:
            self.apply_transaction_to_state(tx)

        self.emit("onBlockAdded", block)
        return block

    minePendingTransactions = mine_pending_transactions

    def add_block(self, block_data: Union[Block, Dict[str, Any]]) -> Dict[str, Any]:
        block = block_data if isinstance(block_data, Block) else Block.from_dict(block_data)
        latest = self.get_latest_block()

        if block.index != latest.index + 1:
            return {"success": False, "reason": "Index mismatch"}
        if block.previousHash != latest.hash:
            return {"success": False, "reason": "Previous hash mismatch"}
        if block.calculate_hash() != block.hash:
            return {"success": False, "reason": "Invalid block hash"}

        for tx in block.transactions:
            check = self.validate_transaction(tx)
            if not check.get("valid"):
                return {"success": False, "reason": f"Invalid transaction in block: {check.get('error')}"}

        self.chain.append(block)
        for tx in block.transactions:
            self.apply_transaction_to_state(tx)

        self.emit("onBlockAdded", block)
        return {"success": True, "block": block}

    addBlock = add_block

    def is_valid_chain(self, chain: List[Union[Block, Dict[str, Any]]]) -> bool:
        if not isinstance(chain, list) or len(chain) == 0:
            return False
        genesis = self.create_genesis_block()

        first_block = chain[0] if isinstance(chain[0], Block) else Block.from_dict(chain[0])
        if first_block.hash != genesis.hash:
            return False

        for i in range(1, len(chain)):
            current = chain[i] if isinstance(chain[i], Block) else Block.from_dict(chain[i])
            previous = chain[i - 1] if isinstance(chain[i - 1], Block) else Block.from_dict(chain[i - 1])

            if current.previousHash != previous.hash:
                return False
            if current.calculate_hash() != current.hash:
                return False

        return True

    isValidChain = is_valid_chain

    def replace_chain(self, new_chain: List[Union[Block, Dict[str, Any]]]) -> bool:
        """
        Nakamoto consensus: adopt longest valid chain.
        """
        if len(new_chain) <= len(self.chain):
            return False
        if not self.is_valid_chain(new_chain):
            return False

        self.chain = [b if isinstance(b, Block) else Block.from_dict(b) for b in new_chain]
        self.state.clear()
        self.key_histories.clear()

        for i in range(1, len(self.chain)):
            for tx in self.chain[i].transactions:
                self.apply_transaction_to_state(tx)

        return True

    replaceChain = replace_chain

    async def init(self) -> bool:
        self.isOnline = True
        return True

    async def register_key(self, peer_id: str, public_key_hex: str, did_uri: str, private_key_hex: str) -> Dict[str, Any]:
        tx = Transaction(
            type=TransactionType.REGISTER_KEY,
            senderPeerId=peer_id,
            payload={"publicKeyHex": public_key_hex, "didUri": did_uri}
        )
        tx.sign(private_key_hex)
        res = self.add_transaction(tx)
        res["transaction"] = tx
        return res

    registerKey = register_key

    async def revoke_key(self, peer_id: str, reason: int = RevocationReason.KEY_COMPROMISE, private_key_hex: str = "") -> Dict[str, Any]:
        tx = Transaction(
            type=TransactionType.REVOKE_KEY,
            senderPeerId=peer_id,
            payload={"reason": reason}
        )
        tx.sign(private_key_hex)
        res = self.add_transaction(tx)
        res["transaction"] = tx
        return res

    revokeKey = revoke_key

    async def unrevoke_key(self, peer_id: str, private_key_hex: str) -> Dict[str, Any]:
        tx = Transaction(
            type=TransactionType.UNREVOKE_KEY,
            senderPeerId=peer_id,
            payload={}
        )
        tx.sign(private_key_hex)
        res = self.add_transaction(tx)
        res["transaction"] = tx
        return res

    unrevokeKey = unrevoke_key

    async def rotate_key(self, peer_id: str, new_public_key_hex: str, new_did_uri: str, current_private_key_hex: str) -> Dict[str, Any]:
        tx = Transaction(
            type=TransactionType.ROTATE_KEY,
            senderPeerId=peer_id,
            payload={"newPublicKeyHex": new_public_key_hex, "newDidUri": new_did_uri}
        )
        tx.sign(current_private_key_hex)
        res = self.add_transaction(tx)
        res["transaction"] = tx
        return res

    rotateKey = rotate_key

    async def resolve_key(self, peer_id: str) -> Optional[Dict[str, Any]]:
        return self.state.get(peer_id)

    resolveKey = resolve_key

    async def verify_key(self, peer_id: str, public_key_hex: str) -> Dict[str, Any]:
        record = self.state.get(peer_id)
        if not record:
            return {"isValid": False, "isRevoked": False, "status": "NOT_REGISTERED"}
        if record.get("isRevoked"):
            return {"isValid": False, "isRevoked": True, "status": "REVOKED"}
        matches = record.get("publicKeyHex", "").lower() == public_key_hex.lower()
        return {
            "isValid": matches,
            "isRevoked": False,
            "status": "ON_CHAIN_VERIFIED" if matches else "KEY_MISMATCH"
        }

    verifyKey = verify_key

    def get_all_registered_peers(self) -> List[str]:
        return list(self.state.keys())

    getAllRegisteredPeers = get_all_registered_peers

    def get_key_history(self, peer_id: str) -> List[str]:
        return self.key_histories.get(peer_id, [])

    getKeyHistory = get_key_history

    def subscribe_events(self, handlers: Dict[str, Any]) -> None:
        for ev in ["onKeyRegistered", "onKeyRevoked", "onKeyUnrevoked", "onKeyRotated", "onBlockAdded"]:
            if ev in handlers and callable(handlers[ev]):
                self.listeners[ev].append(handlers[ev])

    subscribeEvents = subscribe_events

    def emit(self, event_name: str, data: Any) -> None:
        for fn in self.listeners.get(event_name, []):
            try:
                fn(data)
            except Exception:
                pass


BlockchainClient = NativeBlockchain
