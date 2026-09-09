import hashlib
import json
import os
import random
import string
import time
from typing import Dict, Any, Union

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


def generate_key_pair() -> Dict[str, str]:
    """
    Generate a new ECDSA keypair (NIST P-256 / secp256r1 curve).
    Returns DER hexadecimal strings for SPKI (public) and PKCS#8 (private).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    priv_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).hex()

    pub_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).hex()

    return {
        "privateKey": priv_der,
        "publicKey": pub_der
    }


# CamelCase alias for direct parity
generateKeyPair = generate_key_pair


def create_did(peer_id: str, public_key_hex: str) -> Dict[str, Any]:
    """
    Construct a W3C-compliant Decentralized Identifier (DID) Document.
    """
    return {
        "@context": "https://www.w3.org/ns/did/v1",
        "id": f"did:peer:{peer_id}",
        "verificationMethod": [{
            "id": f"did:peer:{peer_id}#key-1",
            "type": "EcdsaSecp256r1VerificationKey2020",
            "controller": f"did:peer:{peer_id}",
            "publicKeyHex": public_key_hex
        }]
    }


createDID = create_did


def sha256(data: Union[str, bytes]) -> str:
    """
    Compute SHA-256 hash of string or bytes, returning hex string.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sign_message(message: Union[str, bytes], private_key_hex: str) -> str:
    """
    Sign a string or byte payload using ECDSA SHA-256 (ASN.1 DER format).
    """
    if isinstance(message, str):
        message = message.encode("utf-8")
    priv_bytes = bytes.fromhex(private_key_hex)
    private_key = serialization.load_der_private_key(priv_bytes, password=None)
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature.hex()


signMessage = sign_message


def verify_message(message: Union[str, bytes], signature_hex: str, public_key_hex: str) -> bool:
    """
    Verify an ECDSA SHA-256 signature against a public key.
    """
    try:
        if isinstance(message, str):
            message = message.encode("utf-8")
        sig_bytes = bytes.fromhex(signature_hex)
        pub_bytes = bytes.fromhex(public_key_hex)
        public_key = serialization.load_der_public_key(pub_bytes)
        public_key.verify(sig_bytes, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError, Exception):
        return False


verifyMessage = verify_message


def compute_shared_secret(private_key_hex: str, public_key_hex: str) -> bytes:
    """
    Compute ECDH Shared Secret from local private key and remote public key.
    """
    priv_bytes = bytes.fromhex(private_key_hex)
    pub_bytes = bytes.fromhex(public_key_hex)
    private_key = serialization.load_der_private_key(priv_bytes, password=None)
    public_key = serialization.load_der_public_key(pub_bytes)
    return private_key.exchange(ec.ECDH(), public_key)


computeSharedSecret = compute_shared_secret


def derive_key(shared_secret: bytes, info: str = "p2p-e2ee-session") -> bytes:
    """
    Derive 256-bit AES symmetric key from shared secret using HKDF-SHA256.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=info.encode("utf-8") if isinstance(info, str) else info
    )
    return hkdf.derive(shared_secret)


deriveKey = derive_key


def encrypt_ecc(plain_text: str, recipient_public_key_hex: str, sender_private_key_hex: str) -> Dict[str, str]:
    """
    End-to-End Encrypt a message using ECIES (ECDH + HKDF + AES-256-GCM).
    """
    shared_secret = compute_shared_secret(sender_private_key_hex, recipient_public_key_hex)
    aes_key = derive_key(shared_secret, "p2p-e2ee-session")

    iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext_with_tag = aesgcm.encrypt(iv, plain_text.encode("utf-8"), None)

    # In AESGCM, the last 16 bytes are the authentication tag
    ciphertext = ciphertext_with_tag[:-16].hex()
    tag = ciphertext_with_tag[-16:].hex()

    return {
        "ciphertext": ciphertext,
        "iv": iv.hex(),
        "tag": tag
    }


encryptECC = encrypt_ecc


def decrypt_ecc(encrypted_data: Dict[str, str], sender_public_key_hex: str, recipient_private_key_hex: str) -> str:
    """
    Decrypt an ECIES-encrypted message.
    """
    shared_secret = compute_shared_secret(recipient_private_key_hex, sender_public_key_hex)
    aes_key = derive_key(shared_secret, "p2p-e2ee-session")

    iv = bytes.fromhex(encrypted_data["iv"])
    data_with_tag = bytes.fromhex(encrypted_data["ciphertext"]) + bytes.fromhex(encrypted_data["tag"])

    aesgcm = AESGCM(aes_key)
    decrypted_bytes = aesgcm.decrypt(iv, data_with_tag, None)
    return decrypted_bytes.decode("utf-8")


decryptECC = decrypt_ecc


def generate_channel_key() -> str:
    """
    Generate a random 256-bit symmetric channel key (hex string).
    """
    return os.urandom(32).hex()


generateChannelKey = generate_channel_key


def encrypt_channel_message(plain_text: str, channel_key_hex: str) -> Dict[str, str]:
    """
    Encrypt a channel message using symmetric AES-256-GCM.
    """
    key = bytes.fromhex(channel_key_hex)
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(iv, plain_text.encode("utf-8"), None)

    ciphertext = ciphertext_with_tag[:-16].hex()
    tag = ciphertext_with_tag[-16:].hex()

    return {
        "ciphertext": ciphertext,
        "iv": iv.hex(),
        "tag": tag
    }


encryptChannelMessage = encrypt_channel_message


def decrypt_channel_message(encrypted_data: Dict[str, str], channel_key_hex: str) -> str:
    """
    Decrypt a channel message using symmetric AES-256-GCM.
    """
    key = bytes.fromhex(channel_key_hex)
    iv = bytes.fromhex(encrypted_data["iv"])
    data_with_tag = bytes.fromhex(encrypted_data["ciphertext"]) + bytes.fromhex(encrypted_data["tag"])

    aesgcm = AESGCM(key)
    decrypted_bytes = aesgcm.decrypt(iv, data_with_tag, None)
    return decrypted_bytes.decode("utf-8")


decryptChannelMessage = decrypt_channel_message


def create_message_envelope(text: str, sender_peer_id: str, private_key_hex: str) -> Dict[str, Any]:
    """
    Construct a timestamped, signed envelope.
    """
    nonce = "".join(random.choices(string.ascii_lowercase + string.digits, k=11))
    payload = {
        "sender": sender_peer_id,
        "timestamp": int(time.time() * 1000),
        "nonce": nonce,
        "text": text
    }
    serialized = json.dumps(payload, separators=(",", ":"))
    signature = sign_message(serialized, private_key_hex)
    return {
        "payload": payload,
        "signature": signature
    }


createMessageEnvelope = create_message_envelope
