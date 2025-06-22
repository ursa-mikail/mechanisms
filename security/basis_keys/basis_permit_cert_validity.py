from cryptography.x509 import load_pem_x509_certificate

def days_left_on_cert(cert_pem: str) -> int:
    cert = load_pem_x509_certificate(cert_pem.encode())
    expiry = cert.not_valid_after_utc
    now = datetime.utcnow().replace(tzinfo=expiry.tzinfo)
    delta = expiry - now
    return delta.days

def display_usage_policies(permit: dict):
    print("\n📋 KEY USAGE POLICIES:")
    policies = permit.get("usage_policies", {})
    for key, terms in policies.items():
        print(f"\n🔐 {key.upper()} KEY POLICY:")
        for field, value in terms.items():
            print(f"  - {field}: {value}")

if __name__ == "__main__":
    PERMIT_FILE = "signed_permit.json"
    # Load and display permit
    with open(PERMIT_FILE, "r") as f:
        permit = json.load(f)

    # Check days left on cert
    cert_pem = permit["identity_cert"]
    days_left = days_left_on_cert(cert_pem)
    print(f"\n📆 Certificate validity: {days_left} days remaining")

    # Display usage policies
    display_usage_policies(permit)

    # Optional: Display full permit and verify
    display_permit(permit)
    print("\nVerifying permit...\n")
    result = verify_permit(permit)
    print("\nResult:", "Valid" if result else "Invalid")

"""
📆 Certificate validity: 699 days remaining

📋 KEY USAGE POLICIES:

🔐 IDENTITY KEY POLICY:
  - purpose: authentication
  - domains: ['login', 'enrollment']

🔐 ATTESTATION KEY POLICY:
  - purpose: hardware_attest
  - max_uses: 10000

🔐 ENDORSEMENT KEY POLICY:
  - purpose: platform_certification

🔐 AUTHORIZATION KEY POLICY:
  - purpose: signature_binding
  - valid_uses: ['permit-signing']

🔐 CIPHERING KEY POLICY:
  - purpose: symmetric_encryption
  - encryption_schemes: ['AES-GCM']

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
"""