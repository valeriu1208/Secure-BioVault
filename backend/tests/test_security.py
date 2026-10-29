import secrets
import unittest
import uuid

import jwt
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from main import (
    JWT_AUDIENCE,
    JWT_ISSUER,
    decrypt_file,
    encrypt_file,
    issue_access_token,
    password_hash,
    parse_opa_decision,
    public_jwk,
)


class PasswordHashTests(unittest.TestCase):
    def test_passwords_are_hashed_with_argon2id(self) -> None:
        encoded = password_hash.hash("a-long-test-password")

        self.assertTrue(encoded.startswith("$argon2id$"))
        self.assertTrue(password_hash.verify("a-long-test-password", encoded))
        self.assertFalse(password_hash.verify("different-password", encoded))


class FileEncryptionTests(unittest.TestCase):
    def test_envelope_encryption_round_trips_and_detects_tampering(self) -> None:
        file_id = uuid.uuid4()
        master_key = secrets.token_bytes(32)
        plaintext = b"private biomedical data"
        encrypted_content, encrypted_dek, iv_nonce = encrypt_file(
            plaintext,
            file_id,
            master_key,
        )

        self.assertEqual(
            decrypt_file(encrypted_content, encrypted_dek, iv_nonce, file_id, master_key),
            plaintext,
        )
        tampered_content = encrypted_content[:-1] + bytes([encrypted_content[-1] ^ 1])
        with self.assertRaises(InvalidTag):
            decrypt_file(tampered_content, encrypted_dek, iv_nonce, file_id, master_key)


class JwtTests(unittest.TestCase):
    def test_access_token_is_ed25519_signed_and_has_oauth_claims(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        user_id = uuid.uuid4()
        access_token, token_id = issue_access_token(user_id, private_key)

        claims = jwt.decode(
            access_token,
            private_key.public_key(),
            algorithms=["EdDSA"],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )

        self.assertEqual(claims["sub"], str(user_id))
        self.assertEqual(claims["jti"], token_id)
        self.assertEqual(jwt.get_unverified_header(access_token)["kid"], "ed25519-v1")
        self.assertEqual(public_jwk(private_key.public_key())["alg"], "EdDSA")


class OpaDecisionTests(unittest.TestCase):
    def test_accepts_boolean_decision_from_opa_data_api(self) -> None:
        self.assertIs(parse_opa_decision({"result": True}), True)
        self.assertIs(parse_opa_decision({"result": False}), False)

    def test_accepts_object_decision_and_rejects_malformed_result(self) -> None:
        self.assertIs(parse_opa_decision({"result": {"allow": True}}), True)
        self.assertIsNone(parse_opa_decision({"result": "allow"}))
        self.assertIsNone(parse_opa_decision({"unexpected": True}))


if __name__ == "__main__":
    unittest.main()
