# src/signature_schemes/ecdsa_scheme.py

from ecdsa import VerifyingKey, BadSignatureError, SECP256k1
import hashlib

def verify_ecdsa_signature(signer_address: str, signature: bytes, signed_hash: bytes) -> bool:
    try:
        # Ensure signer_address is hexadecimal and of correct length
        verifying_key = VerifyingKey.from_string(bytes.fromhex(signer_address), curve=SECP256k1)
        hash_digest = hashlib.sha256(signed_hash).digest()
        return verifying_key.verify(signature, hash_digest)
    except BadSignatureError:
        return False
    except Exception as e:
        print(f"Verification error: {e}")
        return False
