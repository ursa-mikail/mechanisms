"""
🔍 Key Components
5 Key Pairs per Party:
- signing: 1. identity (authentication), 2. attestation, 3. endorsement, 4. authorization.
- ciphering for encryption.

ECDH Exchange:
- Between matching-purpose keys across both parties.

Session Key Derivation:
- HKDF(SHA256) on the concatenated shared secrets:
- SK = KDF(DH1 || DH2 || DH3 || DH4 || DH5)   # root ratchet

"""
#!pip install pycryptodome
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
import os


# Define roles
KEY_PURPOSES = ["identity", "attestation", "endorsement", "authorization", "ciphering"]


def generate_key_pairs():
    """Generate 5 EC private-public key pairs."""
    return {purpose: ec.generate_private_key(ec.SECP256R1()) for purpose in KEY_PURPOSES}


def derive_shared_keys(our_keys, their_public_keys):
    """Perform ECDH between each of our private keys and their corresponding public keys."""
    shared_keys = {}
    for purpose in KEY_PURPOSES:
        shared_secret = our_keys[purpose].exchange(ec.ECDH(), their_public_keys[purpose])
        shared_keys[purpose] = shared_secret
    return shared_keys


def serialize_public_keys(keys):
    """Convert private keys to public keys (PEM format)."""
    return {
        purpose: keys[purpose].public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        for purpose in KEY_PURPOSES
    }


def load_public_keys(peer_serialized_keys):
    """Deserialize received public keys into EC public key objects."""
    return {
        purpose: ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)
        for purpose, pub_bytes in peer_serialized_keys.items()
    }


def kdf_derive_session_key(shared_keys):
    """Combine all shared secrets and derive a single session key."""
    combined = b''.join(shared_keys[purpose] for purpose in KEY_PURPOSES)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"session context",
    )
    return hkdf.derive(combined)


def establish_secure_session():
    # === Party A and B generate their keys ===
    party_a_keys = generate_key_pairs()
    party_b_keys = generate_key_pairs()

    # === Exchange public keys (simulate) ===
    party_a_pub = serialize_public_keys(party_a_keys)
    party_b_pub = serialize_public_keys(party_b_keys)

    # === Deserialize public keys ===
    party_a_peer_keys = load_public_keys(party_b_pub)
    party_b_peer_keys = load_public_keys(party_a_pub)

    # === Each party derives shared symmetric keys ===
    shared_a = derive_shared_keys(party_a_keys, party_a_peer_keys)
    shared_b = derive_shared_keys(party_b_keys, party_b_peer_keys)

    # === Derive final session keys ===
    session_key_a = kdf_derive_session_key(shared_a)
    session_key_b = kdf_derive_session_key(shared_b)

    print("Session keys match:", session_key_a == session_key_b)
    print("Session Key (hex):", session_key_a.hex())


# Run the secure session establishment
if __name__ == "__main__":
    establish_secure_session()

"""
Session keys match: True
Session Key (hex): b3ade6414b66168fd34c153137318a5e2e524f5623b3d49def33e43a57cc2f71
"""