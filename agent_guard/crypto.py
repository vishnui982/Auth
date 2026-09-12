import base64
import binascii
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from .canonical import canonical, fields
from .errors import GuardError

DOMAIN = b"agent-guard/signed-json/v1\x00"


def sign(payload, key: Ed25519PrivateKey):
    return {"payload": payload, "signature": base64.b64encode(
        key.sign(DOMAIN + canonical(payload))).decode("ascii")}


def verify(envelope, key: Ed25519PublicKey):
    fields(envelope, {"payload", "signature"})
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError("signature length")
        if base64.b64encode(signature).decode("ascii") != envelope["signature"]:
            raise ValueError("noncanonical signature encoding")
        key.verify(signature, DOMAIN + canonical(envelope["payload"]))
    except (InvalidSignature, ValueError, TypeError, binascii.Error) as exc:
        raise GuardError("invalid_signature") from exc
    return envelope["payload"]


def public_pem(key):
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def private_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def verifier_hash():
    """Source commitment, not hardware/runtime attestation."""
    root = Path(__file__).parent
    manifest = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(root.glob("*.py"))}
    return hashlib.sha256(canonical(manifest)).hexdigest()
