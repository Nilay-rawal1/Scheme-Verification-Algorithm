import unittest
from src.signature_verifier import SignatureVerifier

class TestSignatureVerifier(unittest.TestCase):
    def setUp(self):
        # Valid signer address as a hexadecimal string (placeholder)
        self.signer_address = "a3c4f37e1234567890abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef"
        self.signed_hash = b"example_hash"  # Placeholder bytes for hash
        # Proper ECDSA signature in bytes format (64 hex characters as an example)
        self.ecdsa_signature = bytes.fromhex("304402207e3d4f74a8ec25d208342a5c04f31b69")

    def test_verify_ecdsa_signature_valid(self):
        verifier = SignatureVerifier(scheme_type="ecdsa")
        result = verifier.verify(self.signer_address, self.ecdsa_signature, self.signed_hash)
        self.assertTrue(result, "ECDSA signature verification should pass for valid signature")

    def test_verify_ecdsa_signature_invalid(self):
        verifier = SignatureVerifier(scheme_type="ecdsa")
        # Use an invalid signature for testing
        invalid_signature = bytes.fromhex("abcdef1234567890abcdefabcdefabcdefabcdefabcdefabcdefabcdef")
        result = verifier.verify(self.signer_address, invalid_signature, self.signed_hash)
        self.assertFalse(result, "ECDSA signature verification should fail for invalid signature")

    def test_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            verifier = SignatureVerifier(scheme_type="unsupported")
            verifier.verify(self.signer_address, self.ecdsa_signature, self.signed_hash)

if __name__ == "__main__":
    unittest.main()
