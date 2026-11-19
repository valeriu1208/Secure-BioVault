import secrets
import unittest
import uuid

from datetime import datetime, timedelta, timezone

import jwt
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fastapi import HTTPException

from audit import (
    AUDIT_GENESIS_HASH,
    compute_log_hash,
    derive_audit_hmac_key,
    verify_audit_chain,
)
from config import JWT_AUDIENCE, JWT_ISSUER, JWT_KEY_ID
from opa import parse_opa_decision
from security import (
    decrypt_file,
    encrypt_file,
    issue_access_token,
    issue_id_token,
    password_hash,
    public_jwk,
    verify_access_token,
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
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.user_id = uuid.uuid4()

    def _sign(self, claims: dict, headers: dict | None = None) -> str:
        now = datetime.now(timezone.utc)
        base = {
            "sub": str(self.user_id),
            "preferred_username": "alice",
            "role": "PATIENT",
            "jti": "x",
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "iat": now,
            "exp": now + timedelta(minutes=5),
        }
        base.update(claims)
        return jwt.encode(
            base,
            self.private_key,
            algorithm="EdDSA",
            headers=headers or {"kid": JWT_KEY_ID, "typ": "at+jwt"},
        )

    def test_access_token_is_ed25519_signed_and_has_oauth_claims(self) -> None:
        access_token = issue_access_token(self.user_id, "alice", "DOCTOR", self.private_key)

        claims = jwt.decode(
            access_token,
            self.public_key,
            algorithms=["EdDSA"],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )
        header = jwt.get_unverified_header(access_token)

        self.assertEqual(claims["sub"], str(self.user_id))
        self.assertEqual(claims["role"], "DOCTOR")
        self.assertEqual(claims["preferred_username"], "alice")
        self.assertLessEqual(claims["exp"] - claims["iat"], 15 * 60)
        self.assertEqual(header["kid"], JWT_KEY_ID)
        self.assertEqual(header["typ"], "at+jwt")
        self.assertEqual(public_jwk(self.public_key)["alg"], "EdDSA")

    def test_access_token_is_validated_statelessly_with_public_key(self) -> None:
        access_token = issue_access_token(self.user_id, "alice", "DOCTOR", self.private_key)

        user = verify_access_token(access_token, self.public_key)

        self.assertEqual(
            user, {"user_id": self.user_id, "username": "alice", "role_name": "DOCTOR"}
        )

    def test_id_token_has_oidc_claims_and_is_not_an_access_token(self) -> None:
        id_token = issue_id_token(self.user_id, "alice", self.private_key, nonce="n-1")

        claims = jwt.decode(
            id_token, self.public_key, algorithms=["EdDSA"],
            audience="biovault-frontend", issuer=JWT_ISSUER,
        )
        self.assertEqual(claims["sub"], str(self.user_id))
        self.assertEqual(claims["nonce"], "n-1")
        self.assertEqual(claims["amr"], ["pwd", "otp"])
        with self.assertRaises(HTTPException):
            verify_access_token(id_token, self.public_key)

    def test_rejects_invalid_access_tokens(self) -> None:
        other_key = Ed25519PrivateKey.generate()
        cases = {
            "expired": self._sign({"exp": datetime.now(timezone.utc) - timedelta(seconds=1)}),
            "wrong audience": self._sign({"aud": "another-api"}),
            "wrong issuer": self._sign({"iss": "evil"}),
            "unknown role": self._sign({"role": "ROOT"}),
            "missing typ": self._sign({}, headers={"kid": JWT_KEY_ID}),
            "signed by other key": jwt.encode(
                {"sub": str(self.user_id)}, other_key, algorithm="EdDSA",
                headers={"typ": "at+jwt"},
            ),
            "alg none": jwt.encode({"sub": str(self.user_id)}, None, algorithm="none"),
        }
        for name, token in cases.items():
            with self.subTest(name), self.assertRaises(HTTPException) as ctx:
                verify_access_token(token, self.public_key)
            self.assertEqual(ctx.exception.status_code, 401)


class OpaDecisionTests(unittest.TestCase):
    def test_accepts_boolean_decision_from_opa_data_api(self) -> None:
        self.assertIs(parse_opa_decision({"result": True}), True)
        self.assertIs(parse_opa_decision({"result": False}), False)

    def test_accepts_object_decision_and_rejects_malformed_result(self) -> None:
        self.assertIs(parse_opa_decision({"result": {"allow": True}}), True)
        self.assertIsNone(parse_opa_decision({"result": "allow"}))
        self.assertIsNone(parse_opa_decision({"unexpected": True}))


class AuditLogHashChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.hmac_key = derive_audit_hmac_key(secrets.token_bytes(32))

    def _build_chain(self, hmac_key: bytes | None = None) -> list[dict]:
        key = hmac_key or self.hmac_key
        ts1 = datetime(2026, 11, 18, 12, 0, 0, 123456, tzinfo = timezone.utc)
        ts2 = datetime(2026, 11, 18, 12, 1, 0, 654321, tzinfo = timezone.utc)
        uid = uuid.uuid4()
        fid = uuid.uuid4()

        h1 = compute_log_hash(
            hmac_key = key,
            prev_hash = AUDIT_GENESIS_HASH,
            user_id = uid,
            action = "LOGIN_ATTEMPT",
            resource_id = None,
            decision = "ALLOWED",
            reason = "Password and TOTP verified",
            ip_address = "127.0.0.1",
            timestamp = ts1,
        )
        h2 = compute_log_hash(
            hmac_key = key,
            prev_hash = h1,
            user_id = uid,
            action = "FILE_READ",
            resource_id = fid,
            decision = "DENIED",
            reason = "OPA decision",
            ip_address = "127.0.0.1",
            timestamp = ts2,
        )
        return [
            {
                "log_id": 1, "user_id": uid, "action": "LOGIN_ATTEMPT",
                "resource_id": None, "decision": "ALLOWED",
                "reason": "Password and TOTP verified", "ip_address": "127.0.0.1",
                "timestamp": ts1, "prev_hash": AUDIT_GENESIS_HASH, "current_hash": h1,
            },
            {
                "log_id": 2, "user_id": uid, "action": "FILE_READ",
                "resource_id": fid, "decision": "DENIED",
                "reason": "OPA decision", "ip_address": "127.0.0.1",
                "timestamp": ts2, "prev_hash": h1, "current_hash": h2,
            },
        ]

    def test_valid_chain_passes_verification(self) -> None:
        result = verify_audit_chain(self._build_chain(), self.hmac_key)
        self.assertTrue(result["valid"])
        self.assertEqual(result["total_logs"], 2)
        self.assertIsNone(result["broken_at_log_id"])

    def test_tampered_row_is_detected(self) -> None:
        rows = self._build_chain()
        rows[1]["decision"] = "ALLOWED"
        result = verify_audit_chain(rows, self.hmac_key)
        self.assertFalse(result["valid"])
        self.assertEqual(result["broken_at_log_id"], 2)

    def test_deleted_row_breaks_chain(self) -> None:
        rows = self._build_chain()
        del rows[0]
        result = verify_audit_chain(rows, self.hmac_key)
        self.assertFalse(result["valid"])
        self.assertEqual(result["broken_at_log_id"], 2)

    def test_forged_chain_with_wrong_key_is_detected(self) -> None:
        forged_rows = self._build_chain(hmac_key=secrets.token_bytes(32))
        result = verify_audit_chain(forged_rows, self.hmac_key)
        self.assertFalse(result["valid"])
        self.assertEqual(result["broken_at_log_id"], 1)


if __name__ == "__main__":
    unittest.main()
