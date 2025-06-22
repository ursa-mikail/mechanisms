import json
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

import os

KEY_PURPOSES = ["identity", "attestation", "endorsement", "authorization", "ciphering"]


def generate_key_pairs():
    return {purpose: ec.generate_private_key(ec.SECP256R1()) for purpose in KEY_PURPOSES}


def generate_self_signed_cert(private_key, subject_name="Party Identity", validity_in_days = 365):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)\
        .public_key(private_key.public_key()).serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.utcnow())\
        .not_valid_after(datetime.utcnow() + timedelta(days=validity_in_days))\
        .sign(private_key, hashes.SHA256())
    return cert.public_bytes(Encoding.PEM)


def serialize_public_keys(keys):
    """Serialize EC public keys to hex."""
    return {
        purpose: keys[purpose].public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        ).hex()
        for purpose in KEY_PURPOSES
    }

def create_unsigned_permit(keypairs, cert_pem):
    pubkeys = serialize_public_keys(keypairs)

    permit = {
        "keys": {
            purpose: {
                "use": purpose,
                "curve": "secp256r1",
                "public_key": pubkeys[purpose]
            }
            for purpose in KEY_PURPOSES
        },
        "identity_cert": cert_pem.decode("utf-8")
    }

    return permit

def sign_permit(permit, authorization_private_key):
    """Sign the full permit and add the signature."""
    # Canonicalized JSON without the signature
    message = json.dumps(permit, sort_keys=True).encode()

    signature = authorization_private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    permit["signature"] = signature.hex()
    return permit


def create_signed_permit(keypairs, cert_pem):
    """Creates a signed permit JSON structure."""
    pubkeys = serialize_public_keys(keypairs)

    permit = {
        "keys": {
            purpose: {
                "use": purpose,
                "curve": "secp256r1",
                "public_key": pubkeys[purpose]
            }
            for purpose in KEY_PURPOSES
        },
        "identity_cert": cert_pem.decode("utf-8")
    }

    # Canonicalize JSON for deterministic signing
    message = json.dumps(permit, sort_keys=True).encode()

    signature = keypairs["authorization"].sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

    permit["signature"] = signature.hex()
    return permit


def verify_permit(permit_json):
    """Verify the permit signature and X.509 certificate validity."""
    # Extract and canonicalize permit (without signature)
    signature = bytes.fromhex(permit_json["signature"])
    permit_copy = {k: v for k, v in permit_json.items() if k != "signature"}
    message = json.dumps(permit_copy, sort_keys=True).encode()

    # Rebuild public key from 'authorization'
    auth_pub_hex = permit_json["keys"]["authorization"]["public_key"]
    auth_pub_bytes = bytes.fromhex(auth_pub_hex)
    auth_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), auth_pub_bytes)

    try:
        auth_pubkey.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        print("✔ Signature is valid.")
    except Exception as e:
        print("✘ Signature verification failed:", str(e))
        return False

    # Parse and validate X.509 identity cert
    try:
        cert = x509.load_pem_x509_certificate(permit_json["identity_cert"].encode())
        pubkey = cert.public_key()
        if isinstance(pubkey, ec.EllipticCurvePublicKey):
            print("✔ X.509 certificate is valid and contains EC public key.")
        else:
            print("✘ Certificate does not contain an EC public key.")
            return False
    except Exception as e:
        print("✘ Certificate parsing failed:", str(e))
        return False

    return True


def add_expiry_and_policies(permit, expiry_days=30):
    expiry = (datetime.utcnow() + timedelta(days=expiry_days)).isoformat() + "Z"
    permit["expiry"] = expiry
    permit["usage_policies"] = {
        "identity": {"purpose": "authentication", "domains": ["login", "enrollment"]},
        "attestation": {"purpose": "hardware_attest", "max_uses": 10000},
        "endorsement": {"purpose": "platform_certification"},
        "authorization": {"purpose": "signature_binding", "valid_uses": ["permit-signing"]},
        "ciphering": {"purpose": "symmetric_encryption", "encryption_schemes": ["AES-GCM"]}
    }
    return permit


import base64

def export_public_keys(keypairs):
    exports = {}
    for purpose, key in keypairs.items():
        pubkey = key.public_key()

        # === Export to PEM format ===
        pem = pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        # === Export to JWK format ===
        numbers = pubkey.public_numbers()
        x_b64 = base64.urlsafe_b64encode(numbers.x.to_bytes(32, byteorder='big')).rstrip(b'=').decode()
        y_b64 = base64.urlsafe_b64encode(numbers.y.to_bytes(32, byteorder='big')).rstrip(b'=').decode()
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": x_b64,
            "y": y_b64,
            "use": purpose,
            "alg": "ES256"
        }

        exports[purpose] = {
            "pem": pem,
            "jwk": jwk
        }

    return exports


from cryptography.x509 import load_pem_x509_certificate

def display_permit(permit):
    print("\n🔐 PERMIT CONTENTS:")
    print(json.dumps(permit, indent=2))

    print("\n📜 X.509 CERTIFICATE INFO:")
    try:
        cert = load_pem_x509_certificate(permit["identity_cert"].encode())
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        print(f"  - Subject     : {subject}")
        print(f"  - Issuer      : {issuer}")
        print(f"  - Valid From  : {not_before}")
        print(f"  - Valid Until : {not_after}")
        print(f"  - Signature Algorithm: {cert.signature_hash_algorithm.name}")
    except Exception as e:
        print("❌ Failed to parse X.509 certificate:", str(e))


# === Main logic with write, delete, load ===
if __name__ == "__main__":
    PERMIT_FILE = "signed_permit.json"
    user_id = 'Ursa Major'
    validity_in_days = 700

    party_keys = generate_key_pairs()
    cert_pem = generate_self_signed_cert(party_keys["identity"], subject_name=user_id, validity_in_days=validity_in_days)

    # Step 1: Create permit
    permit = create_unsigned_permit(party_keys, cert_pem)

    # Step 2: Add expiry and usage policies
    permit = add_expiry_and_policies(permit, expiry_days=validity_in_days)

    # Step 3: Sign the full permit
    permit = sign_permit(permit, party_keys["authorization"])

    # === Write to JSON file ===
    with open(PERMIT_FILE, "w") as f:
        json.dump(permit, f, indent=2)
    print(f"\nPermit written to {PERMIT_FILE}")

    # === Simulate deletion ===
    del permit

    # === Load from file ===
    with open(PERMIT_FILE, "r") as f:
        permit = json.load(f)

    # === Display and verify ===
    display_permit(permit)

    print("\nVerifying permit...\n")
    result = verify_permit(permit)
    print("\nResult:", "Valid" if result else "Invalid")

    print("=== Public Keys ===")
    party_keys = generate_key_pairs()

    key_exports = export_public_keys(party_keys)

    # Print Identity Key in both formats
    print("\n🔑 Identity Key PEM:")
    print(key_exports["identity"]["pem"])

    print("\n🌐 Identity Key JWK:")
    print(json.dumps(key_exports["identity"]["jwk"], indent=2))

"""
Permit written to signed_permit.json

🔐 PERMIT CONTENTS:
{
  "keys": {
    "identity": {
      "use": "identity",
      "curve": "secp256r1",
      "public_key": "044075f2616f560ff5d8f5903d69eb11f02c0f4b334fc029154450d8dafa6925541d215045a9a37ebd64afb568cc08ba4d4d9bba42e387bc81c8af130795710dec"
    },
    "attestation": {
      "use": "attestation",
      "curve": "secp256r1",
      "public_key": "04ee55580cd872634951475cae649942f181e400b389d47c1b1c9095ef8c91b3d5672187181acec46d1b4e72b089d0643089d5fad1be3140b682eec0265ba9ec30"
    },
    "endorsement": {
      "use": "endorsement",
      "curve": "secp256r1",
      "public_key": "04db08562944991a65eddef47815823b5032c950c97956f06cc5da30a22e7045e02a3fc3b61fe6372262c125b5070f7b9146f59699c51ba486b7c7ccb99348a230"
    },
    "authorization": {
      "use": "authorization",
      "curve": "secp256r1",
      "public_key": "0435de71587b11ce76c67f1684ca8f2d23d8c05b13182ab71928fbd766995aec9651b93876412960ceb81752e3a893ed26568ac00263885cce88125e13f35f352c"
    },
    "ciphering": {
      "use": "ciphering",
      "curve": "secp256r1",
      "public_key": "046acebeeeb78c9e4e016760b15369ee8ae5fc40096582e0236488c75627519300754d38bcd486a92c3182f5e800383a3c1de76924f540cf63ed15dd55de85a1f7"
    }
  },
  "identity_cert": "-----BEGIN CERTIFICATE-----\nMIIBKDCB0KADAgECAhRAR6kPBrJZNvw+9XvotbDF8VUrRzAKBggqhkjOPQQDAjAV\nMRMwEQYDVQQDDApVcnNhIE1ham9yMB4XDTI1MDYyMjE5MzE1MVoXDTI3MDUyMzE5\nMzE1MVowFTETMBEGA1UEAwwKVXJzYSBNYWpvcjBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABEB18mFvVg/12PWQPWnrEfAsD0szT8ApFURQ2Nr6aSVUHSFQRamjfr1k\nr7VozAi6TU2bukLjh7yByK8TB5VxDewwCgYIKoZIzj0EAwIDRwAwRAIgFE3NfYKD\nl2MbWVtgRu9R7Ue9qfRNXH4wld+zTIwdTAMCIFc9DO9vVSApCyGr9yWTKcTDkjo7\nfg1L4XBBxksP5tSu\n-----END CERTIFICATE-----\n",
  "expiry": "2027-05-23T19:31:51.820532Z",
  "usage_policies": {
    "identity": {
      "purpose": "authentication",
      "domains": [
        "login",
        "enrollment"
      ]
    },
    "attestation": {
      "purpose": "hardware_attest",
      "max_uses": 10000
    },
    "endorsement": {
      "purpose": "platform_certification"
    },
    "authorization": {
      "purpose": "signature_binding",
      "valid_uses": [
        "permit-signing"
      ]
    },
    "ciphering": {
      "purpose": "symmetric_encryption",
      "encryption_schemes": [
        "AES-GCM"
      ]
    }
  },
  "signature": "3046022100907c321b39fbca15ae8d15f8e2b29d5c51ee892f3210939972b83e1a5add85f2022100ced14426631f0624dc29625c179c97a339dc750001513aab78d0b4f17b67e2de"
}

📜 X.509 CERTIFICATE INFO:
  - Subject     : CN=Ursa Major
  - Issuer      : CN=Ursa Major
  - Valid From  : 2025-06-22 19:31:51+00:00
  - Valid Until : 2027-05-23 19:31:51+00:00
  - Signature Algorithm: sha256

Verifying permit...

✔ Signature is valid.
✔ X.509 certificate is valid and contains EC public key.

Result: Valid
=== Public Keys ===

🔑 Identity Key PEM:
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjT75Vu5q/f5kY+U0Y16DJ+44Bpv6
cfHDZQMWlQ/JSM5ejxiMvpZfSy9xaiBVkRgjckgjqi28xMHc6QEJVVSo4A==
-----END PUBLIC KEY-----


🌐 Identity Key JWK:
{
  "kty": "EC",
  "crv": "P-256",
  "x": "jT75Vu5q_f5kY-U0Y16DJ-44Bpv6cfHDZQMWlQ_JSM4",
  "y": "Xo8YjL6WX0svcWogVZEYI3JII6otvMTB3OkBCVVUqOA",
  "use": "identity",
  "alg": "ES256"
}
"""