from abc import ABC, abstractmethod
import hashlib
import json
import os
import random
import string
import sys
import time
from typing import Dict, Any, Union

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature


# ─────────────────────────────────────────────────────────────────
# 1. Hashing Strategy Interface & Concrete Providers
# ─────────────────────────────────────────────────────────────────

class IHashProvider(ABC):
    """Abstract Strategy for cryptographic hashing."""
    @property
    @abstractmethod
    def name(self) -> str: pass

    @abstractmethod
    def hash(self, data: Union[str, bytes]) -> str:
        """Return hexadecimal hash digest string."""
        pass


class SHA256Provider(IHashProvider):
    """Standard NIST SHA-256 hashing."""
    @property
    def name(self) -> str:
        return "SHA-256"

    def hash(self, data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return hashlib.sha256(data).hexdigest()


class BLAKE2bProvider(IHashProvider):
    """High-speed, cryptographic BLAKE2b (256-bit digest)."""
    @property
    def name(self) -> str:
        return "BLAKE2b-256"

    def hash(self, data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return hashlib.blake2b(data, digest_size=32).hexdigest()


class SHA3_256Provider(IHashProvider):
    """Keccak / SHA-3 (256-bit digest)."""
    @property
    def name(self) -> str:
        return "SHA3-256"

    def hash(self, data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return hashlib.sha3_256(data).hexdigest()


# ─────────────────────────────────────────────────────────────────
# 2. Asymmetric Strategy Interface & Concrete Providers
# ─────────────────────────────────────────────────────────────────

class IAsymmetricProvider(ABC):
    """Abstract Strategy for key generation, signing, verification, and ECDH."""
    @property
    @abstractmethod
    def name(self) -> str: pass

    @abstractmethod
    def generate_keypair(self) -> Dict[str, str]:
        """Return {'privateKey': hex, 'publicKey': hex}."""
        pass

    @abstractmethod
    def sign(self, message: Union[str, bytes], private_key_hex: str) -> str:
        """Sign message and return signature hex string."""
        pass

    @abstractmethod
    def verify(self, message: Union[str, bytes], signature_hex: str, public_key_hex: str) -> bool:
        """Verify signature against public key."""
        pass

    @abstractmethod
    def compute_shared_secret(self, private_key_hex: str, remote_public_key_hex: str) -> bytes:
        """Compute raw shared secret for E2EE key agreement."""
        pass


class NISTP256Provider(IAsymmetricProvider):
    """NIST P-256 / secp256r1 curve with ECDSA and ECDH."""
    @property
    def name(self) -> str:
        return "NIST P-256 (secp256r1)"

    def generate_keypair(self) -> Dict[str, str]:
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        priv_der = priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).hex()
        pub_der = pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
        return {"privateKey": priv_der, "publicKey": pub_der}

    def sign(self, message: Union[str, bytes], private_key_hex: str) -> str:
        if isinstance(message, str):
            message = message.encode("utf-8")
        priv_bytes = bytes.fromhex(private_key_hex)
        private_key = serialization.load_der_private_key(priv_bytes, password=None)
        sig = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return sig.hex()

    def verify(self, message: Union[str, bytes], signature_hex: str, public_key_hex: str) -> bool:
        try:
            if isinstance(message, str):
                message = message.encode("utf-8")
            sig_bytes = bytes.fromhex(signature_hex)
            pub_bytes = bytes.fromhex(public_key_hex)
            public_key = serialization.load_der_public_key(pub_bytes)
            public_key.verify(sig_bytes, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def compute_shared_secret(self, private_key_hex: str, remote_public_key_hex: str) -> bytes:
        priv_bytes = bytes.fromhex(private_key_hex)
        pub_bytes = bytes.fromhex(remote_public_key_hex)
        private_key = serialization.load_der_private_key(priv_bytes, password=None)
        remote_pub = serialization.load_der_public_key(pub_bytes)
        return private_key.exchange(ec.ECDH(), remote_pub)


# ─────────────────────────────────────────────────────────────────
# 3. Symmetric AEAD Cipher Interface & Concrete Providers
# ─────────────────────────────────────────────────────────────────

class ICipherProvider(ABC):
    """Abstract Strategy for Authenticated Encryption with Associated Data (AEAD)."""
    @property
    @abstractmethod
    def name(self) -> str: pass

    @abstractmethod
    def encrypt(self, plain_text: str, key_bytes: bytes) -> Dict[str, str]:
        """Return {'ciphertext': hex, 'iv': hex, 'tag': hex}."""
        pass

    @abstractmethod
    def decrypt(self, encrypted_data: Dict[str, str], key_bytes: bytes) -> str:
        """Decrypt authenticated payload and return plaintext string."""
        pass


class AESGCMProvider(ICipherProvider):
    """AES-256 in Galois/Counter Mode (GCM)."""
    @property
    def name(self) -> str:
        return "AES-256-GCM"

    def encrypt(self, plain_text: str, key_bytes: bytes) -> Dict[str, str]:
        iv = os.urandom(12)
        aesgcm = AESGCM(key_bytes)
        encrypted = aesgcm.encrypt(iv, plain_text.encode("utf-8"), None)
        ciphertext = encrypted[:-16].hex()
        tag = encrypted[-16:].hex()
        return {"ciphertext": ciphertext, "iv": iv.hex(), "tag": tag}

    def decrypt(self, encrypted_data: Dict[str, str], key_bytes: bytes) -> str:
        iv = bytes.fromhex(encrypted_data["iv"])
        payload = bytes.fromhex(encrypted_data["ciphertext"]) + bytes.fromhex(encrypted_data["tag"])
        aesgcm = AESGCM(key_bytes)
        decrypted = aesgcm.decrypt(iv, payload, None)
        return decrypted.decode("utf-8")


class ChaCha20Poly1305Provider(ICipherProvider):
    """ChaCha20 stream cipher with Poly1305 authenticator (RFC 8439)."""
    @property
    def name(self) -> str:
        return "ChaCha20-Poly1305"

    def encrypt(self, plain_text: str, key_bytes: bytes) -> Dict[str, str]:
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(key_bytes)
        encrypted = chacha.encrypt(nonce, plain_text.encode("utf-8"), None)
        ciphertext = encrypted[:-16].hex()
        tag = encrypted[-16:].hex()
        return {"ciphertext": ciphertext, "iv": nonce.hex(), "tag": tag}

    def decrypt(self, encrypted_data: Dict[str, str], key_bytes: bytes) -> str:
        nonce = bytes.fromhex(encrypted_data["iv"])
        payload = bytes.fromhex(encrypted_data["ciphertext"]) + bytes.fromhex(encrypted_data["tag"])
        chacha = ChaCha20Poly1305(key_bytes)
        decrypted = chacha.decrypt(nonce, payload, None)
        return decrypted.decode("utf-8")


# ─────────────────────────────────────────────────────────────────
# 4. Unified CryptoSuite (Strategy Manager)
# ─────────────────────────────────────────────────────────────────

class CryptoSuite:
    """
    Modular Cryptographic Suite combining chosen Hash, Asymmetric, and Cipher providers.
    """
    def __init__(
        self,
        hash_provider: IHashProvider,
        asymmetric_provider: IAsymmetricProvider,
        cipher_provider: ICipherProvider
    ):
        self.hash_provider = hash_provider
        self.asymmetric_provider = asymmetric_provider
        self.cipher_provider = cipher_provider

    @classmethod
    def default(cls) -> "CryptoSuite":
        """Default NIST-compliant suite: SHA-256 + NIST P-256 + AES-256-GCM."""
        return cls(
            hash_provider=SHA256Provider(),
            asymmetric_provider=NISTP256Provider(),
            cipher_provider=AESGCMProvider()
        )

    @classmethod
    def modern_fast(cls) -> "CryptoSuite":
        """High-performance modern suite: BLAKE2b + NIST P-256 + ChaCha20-Poly1305."""
        return cls(
            hash_provider=BLAKE2bProvider(),
            asymmetric_provider=NISTP256Provider(),
            cipher_provider=ChaCha20Poly1305Provider()
        )

    def get_descriptor(self) -> str:
        return f"{self.hash_provider.name} | {self.asymmetric_provider.name} | {self.cipher_provider.name}"

    def hash(self, data: Union[str, bytes]) -> str:
        return self.hash_provider.hash(data)

    def generate_keypair(self) -> Dict[str, str]:
        return self.asymmetric_provider.generate_keypair()

    def sign(self, message: Union[str, bytes], private_key_hex: str) -> str:
        return self.asymmetric_provider.sign(message, private_key_hex)

    def verify(self, message: Union[str, bytes], signature_hex: str, public_key_hex: str) -> bool:
        return self.asymmetric_provider.verify(message, signature_hex, public_key_hex)

    def derive_symmetric_key(self, shared_secret: bytes, info: str = "p2p-e2ee-session") -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"",
            info=info.encode("utf-8") if isinstance(info, str) else info
        )
        return hkdf.derive(shared_secret)

    def encrypt_dm(self, plain_text: str, recipient_public_key_hex: str, sender_private_key_hex: str) -> Dict[str, str]:
        shared_secret = self.asymmetric_provider.compute_shared_secret(sender_private_key_hex, recipient_public_key_hex)
        symmetric_key = self.derive_symmetric_key(shared_secret)
        return self.cipher_provider.encrypt(plain_text, symmetric_key)

    def decrypt_dm(self, encrypted_data: Dict[str, str], sender_public_key_hex: str, recipient_private_key_hex: str) -> str:
        shared_secret = self.asymmetric_provider.compute_shared_secret(recipient_private_key_hex, sender_public_key_hex)
        symmetric_key = self.derive_symmetric_key(shared_secret)
        return self.cipher_provider.decrypt(encrypted_data, symmetric_key)

    def encrypt_channel(self, plain_text: str, channel_key_hex: str) -> Dict[str, str]:
        return self.cipher_provider.encrypt(plain_text, bytes.fromhex(channel_key_hex))

    def decrypt_channel(self, encrypted_data: Dict[str, str], channel_key_hex: str) -> str:
        return self.cipher_provider.decrypt(encrypted_data, bytes.fromhex(channel_key_hex))
