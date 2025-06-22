# Cryptographic Basis

Diffie-Hellman (DH) key exchange between 2 parties, with the generation of 5 key pairs (identity (authentication), attestation, endorsement, authorization, ciphering), and derivation of a session key using a KDF from all 5 DH symmetric keys.

## 🔍 Key Components
- 5 Key Pairs per Party:
	- signing: 1. identity (authentication), 2. attestation, 3. endorsement, 4. authorization.
	- ciphering for encryption.

ECDH Exchange:
- Between matching-purpose keys across both parties.

Session Key Derivation:
- HKDF(SHA256) on the concatenated shared secrets:
- SK = KDF(DH1 || DH2 || DH3 || DH4 || DH5)   # root ratchet


### Requirements: 
cryptography library for ECC key pairs (Elliptic Curve Diffie-Hellman).
HKDF as the Key Derivation Function (KDF).
Curve: e.g. SECP256R1.



✅ Writing the signed permit to a JSON file.
✅ Deleting the in-memory permit (simulated with del permit).
✅ Loading the permit back from file.
✅ Check expiry (ISO timestamp string). Usage_policies per key (e.g., max_uses, domains, purposes)

