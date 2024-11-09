import unittest
from src.signature_verifier import SignatureVerifier
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

class TestSignatureVerifier(unittest.TestCase):
    def setUp(self):
        # Valid ECDSA public key (65 bytes, uncompressed with 0x04 prefix for SECP256k1)
        self.signer_address = "04bfcab3ebc69d23b5b63d7a034bd3466b14f6e3b4f7c9e9af9f4f04f8f8aaba7127b0c37f9b6bd086c2c15f589ece1d7e7aeab85be905c8ae3d55bb92f567cbb3"
        self.signed_hash = hashlib.sha256(b"example message").digest()

        # Compress the public key
        public_key = ec.EllipticCurvePublicNumbers(
            x=int(self.signer_address[2:], 16),
            y=int(self.signer_address[66:], 16),
            curve=ec.SECP256K1()
        ).public_key(ec.SECP256K1())
        self.compressed_signer_address = compress_public_key(public_key.public_bytes(
            encoding='raw',
            format='compressed'
        )).hex()
        
        # ECDSA signature in bytes format for testing
        self.ecdsa_signature = bytes.fromhex("304402200e3d4f73a8ec45d207842a5c03e81c7d1c060ca125e8d3af86d5b7f1")

    def test_verify_ecdsa_signature_valid(self):
        verifier = SignatureVerifier(scheme_type="ecdsa")
        result = verifier.verify(self.compressed_signer_address, self.ecdsa_signature, self.signed_hash)
        self.assertTrue(result, "ECDSA signature verification should pass for valid signature")

    def test_verify_ecdsa_signature_invalid(self):
        verifier = SignatureVerifier(scheme_type="ecdsa")
        # Use an invalid signature for testing
        invalid_signature = bytes.fromhex("abcdef1234567890abcdefabcdefabcdefabcdefabcdefabcdefabcdef")
        result = verifier.verify(self.compressed_signer_address, invalid_signature, self.signed_hash)
        self.assertFalse(result, "ECDSA signature verification should fail for invalid signature")

    def test_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            verifier = SignatureVerifier(scheme_type="unsupported")
            verifier.verify(self.compressed_signer_address, self.ecdsa_signature, self.signed_hash)

if __name__ == "__main__":
    unittest.main()


