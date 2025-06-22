def renew_self_signed_cert_with_same_key(private_key, subject_name: str, validity_days=365):
    """
    Generate a new self-signed cert using the *same* EC private key,
    with updated validity period and subject.
    """
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM)


# Usage
if __name__ == "__main__":
    PERMIT_FILE = "signed_permit.json"
    validity_in_days = 1000
    print("♻️ Auto-renewing certificate with same key...")
    new_cert_pem = renew_self_signed_cert_with_same_key(
        party_keys["identity"], user_id, validity_days=validity_in_days
    )

    permit["identity_cert"] = new_cert_pem.decode("utf-8")

    # Re-sign the permit with updated cert
    permit = sign_permit(permit, party_keys["authorization"])

    # Save renewed permit
    with open(PERMIT_FILE, "w") as f:
        json.dump(permit, f, indent=2)

    print("✅ Permit renewed and re-signed with updated certificate.")

"""
♻️ Auto-renewing certificate with same key...
✅ Permit renewed and re-signed with updated certificate.
"""