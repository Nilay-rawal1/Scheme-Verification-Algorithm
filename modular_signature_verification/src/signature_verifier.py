# src/signature_verifier.py
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
import hashlib
from typing import Union

class SignatureVerifier:
    def __init__(self, scheme_type: str):
        self.scheme_type = scheme_type

    def verify(self, signer_address: str, signature: bytes, signed_hash: bytes) -> bool:
        if self.scheme_type == "ecdsa":
            return self.verify_ecdsa_signature(signer_address, signature, signed_hash)
        else:
            raise ValueError("Unsupported signature scheme")

    def verify_ecdsa_signature(self, signer_address: str, signature: bytes, signed_hash: bytes) -> bool:
        try:
            verifying_key = VerifyingKey.from_string(bytes.fromhex(signer_address), curve=SECP256k1)
            hash_digest = hashlib.sha256(signed_hash).digest()
            return verifying_key.verify(signature, hash_digest)
        except BadSignatureError:
            return False
        except Exception as e:
            print(f"Verification error: {e}")
            return False
