#!pip install sslib
import os
import json
import random
from hashlib import sha256
from sslib import shamir
from typing import List

""" generate key without name order
def generate_keys(key_names: List[str], key_length: int) -> dict:
    keys = {}
    for name in key_names:
        key_bytes = os.urandom(key_length)
        keys[name] = key_bytes.hex()
        print(f"SHA256({name}) = {sha256(key_bytes).hexdigest()}")
    return keys
"""
def generate_keys(key_names: List[str], key_length: int) -> dict:
    keys = {}
    for idx in range(len(key_names)):
        name = key_names[idx]
        key_bytes = os.urandom(key_length)
        keys[name] = key_bytes.hex()
        print(f"SHA256({name}) = {sha256(key_bytes).hexdigest()}")
    return keys

def sha256_of_json(obj: dict) -> str:
    json_bytes = json.dumps(obj, sort_keys=True).encode('utf-8')
    return sha256(json_bytes).hexdigest()

def pretty_print_json(obj: dict):
    print(json.dumps(obj, indent=4, sort_keys=True))

def shamir_split(secret: str, k: int, n: int): 
    secret_bytes = secret.encode('utf-8')
    return shamir.to_base64(shamir.split_secret(secret_bytes, k, n))

def shamir_combine(shares):
    combined = shamir.recover_secret(shamir.from_base64(shares))
    return combined.decode('utf-8')

def show_shares(shares_of_key, number_of_shares):
    print(f"prime_mod: {shares_of_key['prime_mod']}")

    for i in range(number_of_shares):
        print(f"share_{i}: {shares_of_key['shares'][i]}")


# --- Parameters ---
N_BYTES = 32
KEY_NAMES = ['root_key_encryption', 'policy_encryption', 'key_ursa', 'key_major']
N_SHARES = 5
K_THRESHOLD = 3  # Minimum number of shares needed to reconstruct

# Step 1: Generate keys
print("Generating keys...")
keys = generate_keys(KEY_NAMES, N_BYTES)

# Step 2: Format and hash JSON
print("\nFormatted JSON:")
pretty_print_json(keys)

print("\nSHA256(JSON):")
json_str = json.dumps(keys, sort_keys=True)
json_hash = hashlib.sha256(json_str.encode()).hexdigest()
print(json_hash)

shares_of_keys_split = []

parsed_keys = json.loads(json_str)
count = 0

# Step 3: Shamir split
# Access and print each key name and its value
for key_name, key_value in parsed_keys.items():
    print(f"Key Name: {key_name}")
    print(f"Key Value: {key_value}")
    print(f"\nSplitting secret with threshold {K_THRESHOLD} of {N_SHARES}...")
    shares_of_keys_split.append(shamir_split(key_value, K_THRESHOLD, N_SHARES))
    show_shares(shares_of_keys_split[count], N_SHARES)
    count += 1


# Step 4: Recombine and verify (with all shares given)
keys_collected = []
"""
for i in range(0, count):
    print(f"\nReconstructing key_{i}...")
    reconstructed = shamir_combine(shares_of_keys_split[i])
    print(reconstructed)
""" 

# Step 4: Recombine and verify (with randomly selected k shares given)
for i in range(count):
    print(f"\nReconstructing key_{i}...")

    # Get full share dictionary
    full_share_dict = shares_of_keys_split[i]

    # Select K_THRESHOLD random shares
    selected_shares = random.sample(full_share_dict["shares"], K_THRESHOLD)

    # Build a reconstruction dictionary with the same format as original
    partial_share_dict = {
        "required_shares": K_THRESHOLD,
        "prime_mod": full_share_dict["prime_mod"],
        "shares": selected_shares
    }

    # Combine and decode
    reconstructed = shamir_combine(partial_share_dict)
    keys_collected.append(reconstructed)
    
    # Verify match
    original = list(parsed_keys.values())[i]
    print(f"Reconstructed key_{i}: {reconstructed}")
    print(f"Original key_{i}     : {original}")
    print("Match:", reconstructed == original)


# reverse keys_collected list
keys_collected = keys_collected[::-1]

# reconstruct json and verify
print("\nFormatted JSON:")
# Recombine key-value dictionary using original key names
# reconstructed_keys = dict(zip(KEY_NAMES, keys_collected)) # dict(zip(...)) doesn't guarantee the original key order will match the collected keys unless the order in keys_collected corresponds exactly to KEY_NAMES. Since the reconstruction loop uses i, it's safer to explicitly construct the dictionary with the known order.
# Recombine key-value dictionary using correct order
reconstructed_keys = {}
for idx in range(len(KEY_NAMES)):
    key_name = KEY_NAMES[idx]
    reconstructed_keys[key_name] = keys_collected[idx]
    print(f"Key Name: {key_name}")
    print(f"Key Value: {keys_collected[idx]}")

pretty_print_json(reconstructed_keys)

# Compute hash of the reconstructed JSON
print("\nSHA256(Reconstructed JSON):")
reconstructed_json_hash = sha256_of_json(reconstructed_keys)
print(reconstructed_json_hash)

# Compare against original hash
print("\n✅ Match with original hash:", reconstructed_json_hash == json_hash)


"""
Generating keys...
SHA256(root_key_encryption) = 2d833554566c3eaf858e1a4fc404f77faeb298e5638443e2ec04c8a95cf6b1d3
SHA256(policy_encryption) = ae165c4085f43b7839ef61f491c63f20c746cdd53183019650e5f28011a61ae1
SHA256(key_ursa) = 18e7b2ebbbd85413b3b18c666f7735e991da7111315c39d4bd19405fa3ee16ec
SHA256(key_major) = 1fb5d260863653b0f8a8f9f4b1feeb8d98a94c99ff91ff69090aed14e05360f6

Formatted JSON:
{
    "key_major": "86a8b31730cb6561a4200c218cd2fba8a528cc5418007eb298053f24a142184e",
    "key_ursa": "3fe320f4a919091e62c502c9f8123e854525d0136f119ff00ad88ecfdbbf75b2",
    "policy_encryption": "02843b3921238a1992a47c69894a9b122f35d896fc919a3b3ad3a2dd132795cc",
    "root_key_encryption": "93a936f02905e38ef36f79d2be8303c567b6db8e75a87428eb222f5cfd8b2719"
}

SHA256(JSON):
fa852a65ea3cf10f6d1936b08ab0eb781f33c7adb7e06bfbfe7f432a93b2da7f
Key Name: key_major
Key Value: 86a8b31730cb6561a4200c218cd2fba8a528cc5418007eb298053f24a142184e

Splitting secret with threshold 3 of 5...
prime_mod: Af//////////////////////////////////////////////////////////////////////////////////////
share_0: 1-uiIRrse8OjxqK8LkRSe3kI+JvRtU5EmMEW55p27FYbqp8qwzJZs68713lzdChKqKQ5A3p0rY5PkZhp4lakll6xg=
share_1: 2-fKiFvicGl14sObZjg6kMyit4feQha7Kws/4Uozon83tApVQ7tE1cdjuFDuIyd/W8/6eRniVpR6jECwM20FBVqlM=
share_2: 3-AXHLko9WQUqWfV0K4R26NOMFLXaMlcaeoBjnNFeUjhei/HktS+R5x7yuWZ8xABFG+mZ/RhTE5I5BM+5gaGRGB3IV
share_3: 4-AZmLOCJVbFPlXZXAXRNbL9scqKcUsfUNWkAp2MR9984x3W43Y7YgfMcV9Ugjq1CeQngXVQspSrjCaTC1uiYqe0Jf
share_4: 5-8+d2dySHs0rM49bXZIv9snHqD3x19v7fKcYB6fZlFyfjhHKDKUF7lXJYCbo0NfuVNG++gVKbxyxj0gMsFf2xGzE=
Key Name: key_ursa
Key Value: 3fe320f4a919091e62c502c9f8123e854525d0136f119ff00ad88ecfdbbf75b2

Splitting secret with threshold 3 of 5...
prime_mod: Af//////////////////////////////////////////////////////////////////////////////////////
share_0: 1-7U2Wpr9Co5VXQyKybJvfwuxIl5QZgDQMUhiP9bz0dyc0WbAOE+ifJjymUxo5Tr0LpTh5G+ySbbQHLc1sJh4xIV4=
share_1: 2-6a2F+1seyE3Y8Or41rr2/IfXdMu7emn1u94AnEvwJDDzu6Op2cuPOzx8XzbJv4lW6EBMOnr6/vXtHkwJ24VCdIg=
share_2: 3-H1M0YwbGno+5apIEd41+3jfiygobHtQfdraKJN8mbFVzWhAFhw0AcDK4iobii8tH+Ufav+NyGSkYNd47hmxpW7A=
share_3: 4-jj6h3cI6Jlr4sBfVTxN3Z/xql084bXKJgqIsj3aXT5SzNPUhG6zyxR9a1QqDs4Le2E8krCX3vE2IdIQBJtOl1tU=
share_4: 5-Nm/Oa415X6+WwXxrXUzgmdVu3JsTZkUz36Dn3BJCze6zTFL8l6tmOgJjPsGtNrAbhVYp/0KL6GM92j1avLr35fg=
Key Name: policy_encryption
Key Value: 02843b3921238a1992a47c69894a9b122f35d896fc919a3b3ad3a2dd132795cc

Splitting secret with threshold 3 of 5...
prime_mod: Af//////////////////////////////////////////////////////////////////////////////////////
share_0: 1-ASCT2vAcy4fk74knfb2h5Tua/QyjsNvHv353VWhRrkgT3+sHoDnio+/jECKYzDjNanpG2Op7ijjnC1i5Ri8ymCBV
share_1: 2-o9TJQqr1mw+tuJxVH+ZWFbPKTu44F1oUvgcm3XQLJxCcCwnPtwCAtkw0LhbAJoMi4PSp5CAQnwrig+9kHL50Bro=
share_2: 3-s/L9L96xm7NzwI+4WgWzv4Og+UDJ6ho19+etk8hP/ydmkmzBrL3OjHHShbMNAoJcljzUUSD0ZM/pstWL/9zJFpE=
share_3: 4-AVDudre3/4nQQaEBp2v//jkKgQubZlQIIywY6YtOfNBYP4EwdhsajXJT6yltsszLF5ofWDF+NYo2IOVrvdiNl0/a
share_4: 5-esc12jbfZWYXWfIiVdU1gkhqhf4NVSPcWpraxAaRmqMm11TtAha9Z/J+GUaxhV1T7Jw1hTfUDz2IG7H5ptDespY=
Key Name: root_key_encryption
Key Value: 93a936f02905e38ef36f79d2be8303c567b6db8e75a87428eb222f5cfd8b2719

Splitting secret with threshold 3 of 5...
prime_mod: Af//////////////////////////////////////////////////////////////////////////////////////
share_0: 1-AR1CmgFw5VLirfCBSnzQTYDknpDMIYaJh5qMBCp5LB/PrEHmOGgQsRXFGtCmpNQUfDLn1uCf044xCaMq8lYM0AGI
share_1: 2-AeeyE7le62Au+vc7Lb68+RhzDrUyxtj4GsjFXjhZi/RuHIGiLnuLfKJTcj3xBkUVFZqd0uoX9IChxUvKg1ko/JXC
share_2: 3-iYegiQNFXksXRmbZ+ys1/xC2oGpWLoUdvQ5zYdRPsT6F9WtEcNTE3hA9fUBcijX+b4dWTpqVPYeWYELra4a87eg=
share_3: 4-AQLDQHBd8003At4ETzIbBDS9llJyz4cwkHdnQ6bpd1ZA6J1Bekfsicj7fI6Up6N3NrGkYQ4ntcTifOCUKo0mEQn4
share_4: 5-AVNk829u9Szyvb4TjWOMY7l5rctMMuL6cvfPzweZAuN1RHkk0ADSy2MVL3Ht55DYvmD08yi/VhayeMy+QL4G+Onz

Reconstructing key_0...
Reconstructed key_0: 86a8b31730cb6561a4200c218cd2fba8a528cc5418007eb298053f24a142184e
Original key_0     : 86a8b31730cb6561a4200c218cd2fba8a528cc5418007eb298053f24a142184e
Match: True

Reconstructing key_1...
Reconstructed key_1: 3fe320f4a919091e62c502c9f8123e854525d0136f119ff00ad88ecfdbbf75b2
Original key_1     : 3fe320f4a919091e62c502c9f8123e854525d0136f119ff00ad88ecfdbbf75b2
Match: True

Reconstructing key_2...
Reconstructed key_2: 02843b3921238a1992a47c69894a9b122f35d896fc919a3b3ad3a2dd132795cc
Original key_2     : 02843b3921238a1992a47c69894a9b122f35d896fc919a3b3ad3a2dd132795cc
Match: True

Reconstructing key_3...
Reconstructed key_3: 93a936f02905e38ef36f79d2be8303c567b6db8e75a87428eb222f5cfd8b2719
Original key_3     : 93a936f02905e38ef36f79d2be8303c567b6db8e75a87428eb222f5cfd8b2719
Match: True

Formatted JSON:
Key Name: root_key_encryption
Key Value: 93a936f02905e38ef36f79d2be8303c567b6db8e75a87428eb222f5cfd8b2719
Key Name: policy_encryption
Key Value: 02843b3921238a1992a47c69894a9b122f35d896fc919a3b3ad3a2dd132795cc
Key Name: key_ursa
Key Value: 3fe320f4a919091e62c502c9f8123e854525d0136f119ff00ad88ecfdbbf75b2
Key Name: key_major
Key Value: 86a8b31730cb6561a4200c218cd2fba8a528cc5418007eb298053f24a142184e
{
    "key_major": "86a8b31730cb6561a4200c218cd2fba8a528cc5418007eb298053f24a142184e",
    "key_ursa": "3fe320f4a919091e62c502c9f8123e854525d0136f119ff00ad88ecfdbbf75b2",
    "policy_encryption": "02843b3921238a1992a47c69894a9b122f35d896fc919a3b3ad3a2dd132795cc",
    "root_key_encryption": "93a936f02905e38ef36f79d2be8303c567b6db8e75a87428eb222f5cfd8b2719"
}

SHA256(Reconstructed JSON):
fa852a65ea3cf10f6d1936b08ab0eb781f33c7adb7e06bfbfe7f432a93b2da7f

✅ Match with original hash: True

Note:
Generate cryptographic keys (e.g., key_00 ... key_XX)
Hash and securely split each key using Shamir's Secret Sharing (SSS)
Recombine keys from partial shares
Validate that the recombined keys match the originals (via SHA-256)

📋 Workflow Summary
1. Key Generation
Generates N-byte random keys using os.urandom.
Keys are printed in hex with their individual SHA256 hashes.

2. JSON Formatting & Hashing
Keys are serialized into JSON (sorted by key).
SHA-256 hash of the entire JSON object is computed for later verification.

3. Shamir Split
Each key is split into N_SHARES using threshold K_THRESHOLD.
Shares are base64 encoded using sslib.shamir.to_base64().
Each share and the prime modulus are printed for each key.

4. Shamir Recombine
For each key, randomly selects K_THRESHOLD shares.
Reconstructs the key using sslib.shamir.recover_secret().
Verifies reconstructed key matches the original hex string.

5. Reconstruct JSON & Final Verification
Rebuilds the key-value JSON using KEY_NAMES and collected keys.
Pretty prints the reconstructed JSON.
Recomputes SHA-256 hash of the reconstructed JSON.
Compares against original hash to verify full integrity.

🧪 Validation
Confirms both:
Each key reconstructed matches its original value
Full reconstructed JSON matches the original JSON hash
"""