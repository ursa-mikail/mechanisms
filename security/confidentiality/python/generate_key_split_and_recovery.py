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

# store key_names
print("\nFormatted JSON (key_names) before writing to key_names.json:")
pretty_print_json(KEY_NAMES)

with open('key_names.json', 'w') as f:
    json.dump(KEY_NAMES, f)

# store json 
print("\nFormatted JSON (shares_of_keys_split) before writing to shares_of_keys_split.json:")
pretty_print_json(shares_of_keys_split)

with open('shares_of_keys_split.json', 'w') as f:
    json.dump(shares_of_keys_split, f)

del shares_of_keys_split
del KEY_NAMES

# print(f"KEY_NAMES: {KEY_NAMES}")

# read key_names
with open('key_names.json', 'r') as f:
    KEY_NAMES = json.load(f)

print(f"KEY_NAMES: {KEY_NAMES}")

# read json
with open('shares_of_keys_split.json', 'r') as f:
    shares_of_keys_split = json.load(f)



print("\nFormatted JSON (shares_of_keys_split) after reading from shares_of_keys_split.json:")
pretty_print_json(shares_of_keys_split)

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
SHA256(root_key_encryption) = ebbafb6830df94d9f9093c2aca43b5de3c50f3f3747200edb41ad79e74af2626
SHA256(policy_encryption) = 3bfcbca65c3905c4544bc0008b049b8d4e8d722ad85324a9f502741d9d589dd1
SHA256(key_ursa) = 64336c297f50018772f74f93882c41ff5d6d5c523d0c4e0f13e9306eb1246540
SHA256(key_major) = 2c5bc606a3f17dcd5096dd9f4cbeecb68d65b98223f61d05cf4bb623c5a8e24f

Formatted JSON:
{
    "key_major": "39964b5303318f7ed23a35425a220fdbd1cdbbf2a4c99c4fd49322c1f731aded",
    "key_ursa": "53365b6d12662ee8047a5c0279d2c325d50e7a0774e113a06e4dc16eae1dc3d2",
    "policy_encryption": "ba13616e57d92fc94c121da8d10108cbde50b8b556ccaf93d1190bd755a70897",
    "root_key_encryption": "c2dabdde201c5dd65622675c6b4ef1d584cbbc64a4f19dee2d9bdda279ca20d9"
}

SHA256(JSON):
fc68cf1b4eda2d6b69181bb2916e0d9695771fc97e547271d9df4ff6fd4cd0b1
Key Name: key_major
Key Value: 39964b5303318f7ed23a35425a220fdbd1cdbbf2a4c99c4fd49322c1f731aded

Splitting secret with threshold 3 of 5...
prime_mod: Af//////////////////////////////////////////////////////////////////////////////////////
share_0: 1-AYcjQ2Y8CiXu6i9WkKSIXye0vpRVXsE5KXF5SES5+U+PLht/OAJhoH4Z1dOc8uKh/qWzRqDy0IfaQtydqO/vkpne
share_1: 2-AZtssC1fi7JqPzoilp+jALWoQDYpssmMa5g8yE/5xGy1zRZ2U+iQGsArEJKHKZ/PKYyOSDTiSI1+TQvAozw/cP+H
share_2: 3-Zw9/jqC5B6cyUJdFIohK4T/pF7BdTC76pn/hU/GRvdg/VRa3Fu3RLGYRcSHdcOq1GvU49QGaQ09P86AiFlD/ll8=
share_3: 4-AeoLsYn/kiWlw3K0nC04Pap7uTjpXkkg1pxCk1ChYUL2hNdgYY16w8LK2G9tDlX0oVDoGOFQxalNS5Q8JX4kPl5k
share_4: 5-JGFGH3wXDGXyoHqbv7LZEVuwmdS1wGH/eYTeRgky/BCdnVNTTDbyg1lljWi8TuzuLmbn+c/Kv3g/7ZStc7ktV5k=
Key Name: key_ursa
Key Value: 53365b6d12662ee8047a5c0279d2c325d50e7a0774e113a06e4dc16eae1dc3d2

Splitting secret with threshold 3 of 5...
prime_mod: Af//////////////////////////////////////////////////////////////////////////////////////
share_0: 1-AfLvTtEOT1Q7k0K/HOHqN2iQdrciV/uxG5NyhxO071zRLfkzm3AupRGceEVuFoMrgrdgj0Caywc3bnIOj6biU0yP
share_1: 2-ARkvcdNMdkKTrYQUn+mcVdqdhYvwJQFDXCHzYRQ1ekZiiRI9TTBmxoeSzalH7ktnRYpNMzhf6q6T2EZMySZGZ69h
share_2: 3-AZz1nDnwqi0+svUyv01IwLtfXLKgyEYZ8d25x2W0A+/mRq9SRaXfxZIaN1/yuInmqaj8URuzwidLot4f3eKPcIym
share_3: 4-AX5BzgT66xQ8o5YZewzveArV/Cs0Qco03MbFuggwjFlcZtByhNCZojEytWludT6prxNt6OqWUXFezjmHzdu9beRf
share_4: 5-vRQHNGs4941/ZsjTKJB7yQFj9aqRjZQc3Rc4+6sTgsTpdZ4KsJRcZNxHxbskabBVyaH6pQeYjM1aWISZEdBftow=
Key Name: policy_encryption
Key Value: ba13616e57d92fc94c121da8d10108cbde50b8b556ccaf93d1190bd755a70897

Splitting secret with threshold 3 of 5...
prime_mod: Af//////////////////////////////////////////////////////////////////////////////////////
share_0: 1-zF72YHE4f0WrohdRxzaVwPRj1Bwjsu5uCE+Xui2KKq20pt+jlu440hqlFuVYtYu13WJ8gllYYGLw0weLQFJrTts=
share_1: 2-AVHfwxLvFmOd2o4orV7e3n37+FG9SVtOCeQBBoAyQLbUE5I0eK7uf0hD0I7cdQI3A2MV8dzeaHQbE2+x/LxxQm3s
share_2: 3-Abrkx0isz94+8flrdwArQJpP8dwUoyqDNMt4fYI/U9zWfyZjtHhjC8Swt55IuEdoIcR+kUDIYJ2Mnws0tauMvZZq
share_3: 4-B24DAapk7yjx49+uqxu8FfBQcyIxII3uvrX8wFTDnLT3Y21W80veR2FaRSoihR8RAZxarhdA3LeTpY+2DaTcyFY=
share_4: 5-N3t2PefVllvaTYVUX7BQ8N0UFuXzPW43vbmEOnKP9m98SVFgH6j20FW4g4Czu1vRGm9OJMsJMZvxPsL94rmgA64=
Key Name: root_key_encryption
Key Value: c2dabdde201c5dd65622675c6b4ef1d584cbbc64a4f19dee2d9bdda279ca20d9

Splitting secret with threshold 3 of 5...
prime_mod: Af//////////////////////////////////////////////////////////////////////////////////////
share_0: 1-f8hn9k+6y2Pig5JDMYAvrcKclqarhbcD+Q3ufUbYTfEdi9nbN333x+DybUvBlKoFH9UL27D+YgoZ793Jl0ni2JY=
share_1: 2-AVDxEzg7RfAFgEnSkpfMO5wfHh9APcpCk0ifrfyvHiWmtBQ8aidVuvxnjfxX9Wm+Q/XF5aKWZHSrl/pbFl8NkxYI
share_2: 3-nd00KiQD0kk+hPEflhmIL0u5z/7pA9njUeugsp43uIT40VwQMems08gz4YrMuKEh5wTxjhKWnEWsVrFJuH1BHJA=
share_3: 4-ZozKzAn0ci8dNO3qLGgVZ0hvqOKtMnz0FPHGnxQlBovrwzjNVznNTgLkHORHgVKe85IvniWU2NhXBOBjo5js7C0=
share_4: 5-qv/XHe0Xz7ccWcjyWrfjRBU/qeuKVivFkbIfwhDmD7uM6dKhl0YcaxeermRlw9K7G22f0s9fKmOYBOhkIGCWhN8=

Formatted JSON (key_names) before writing to key_names.json:
[
    "root_key_encryption",
    "policy_encryption",
    "key_ursa",
    "key_major"
]

Formatted JSON (shares_of_keys_split) before writing to shares_of_keys_split.json:
[
    {
        "prime_mod": "Af//////////////////////////////////////////////////////////////////////////////////////",
        "required_shares": 3,
        "shares": [
            "1-AYcjQ2Y8CiXu6i9WkKSIXye0vpRVXsE5KXF5SES5+U+PLht/OAJhoH4Z1dOc8uKh/qWzRqDy0IfaQtydqO/vkpne",
            "2-AZtssC1fi7JqPzoilp+jALWoQDYpssmMa5g8yE/5xGy1zRZ2U+iQGsArEJKHKZ/PKYyOSDTiSI1+TQvAozw/cP+H",
            "3-Zw9/jqC5B6cyUJdFIohK4T/pF7BdTC76pn/hU/GRvdg/VRa3Fu3RLGYRcSHdcOq1GvU49QGaQ09P86AiFlD/ll8=",
            "4-AeoLsYn/kiWlw3K0nC04Pap7uTjpXkkg1pxCk1ChYUL2hNdgYY16w8LK2G9tDlX0oVDoGOFQxalNS5Q8JX4kPl5k",
            "5-JGFGH3wXDGXyoHqbv7LZEVuwmdS1wGH/eYTeRgky/BCdnVNTTDbyg1lljWi8TuzuLmbn+c/Kv3g/7ZStc7ktV5k="
        ]
    },
    {
        "prime_mod": "Af//////////////////////////////////////////////////////////////////////////////////////",
        "required_shares": 3,
        "shares": [
            "1-AfLvTtEOT1Q7k0K/HOHqN2iQdrciV/uxG5NyhxO071zRLfkzm3AupRGceEVuFoMrgrdgj0Caywc3bnIOj6biU0yP",
            "2-ARkvcdNMdkKTrYQUn+mcVdqdhYvwJQFDXCHzYRQ1ekZiiRI9TTBmxoeSzalH7ktnRYpNMzhf6q6T2EZMySZGZ69h",
            "3-AZz1nDnwqi0+svUyv01IwLtfXLKgyEYZ8d25x2W0A+/mRq9SRaXfxZIaN1/yuInmqaj8URuzwidLot4f3eKPcIym",
            "4-AX5BzgT66xQ8o5YZewzveArV/Cs0Qco03MbFuggwjFlcZtByhNCZojEytWludT6prxNt6OqWUXFezjmHzdu9beRf",
            "5-vRQHNGs4941/ZsjTKJB7yQFj9aqRjZQc3Rc4+6sTgsTpdZ4KsJRcZNxHxbskabBVyaH6pQeYjM1aWISZEdBftow="
        ]
    },
    {
        "prime_mod": "Af//////////////////////////////////////////////////////////////////////////////////////",
        "required_shares": 3,
        "shares": [
            "1-zF72YHE4f0WrohdRxzaVwPRj1Bwjsu5uCE+Xui2KKq20pt+jlu440hqlFuVYtYu13WJ8gllYYGLw0weLQFJrTts=",
            "2-AVHfwxLvFmOd2o4orV7e3n37+FG9SVtOCeQBBoAyQLbUE5I0eK7uf0hD0I7cdQI3A2MV8dzeaHQbE2+x/LxxQm3s",
            "3-Abrkx0isz94+8flrdwArQJpP8dwUoyqDNMt4fYI/U9zWfyZjtHhjC8Swt55IuEdoIcR+kUDIYJ2Mnws0tauMvZZq",
            "4-B24DAapk7yjx49+uqxu8FfBQcyIxII3uvrX8wFTDnLT3Y21W80veR2FaRSoihR8RAZxarhdA3LeTpY+2DaTcyFY=",
            "5-N3t2PefVllvaTYVUX7BQ8N0UFuXzPW43vbmEOnKP9m98SVFgH6j20FW4g4Czu1vRGm9OJMsJMZvxPsL94rmgA64="
        ]
    },
    {
        "prime_mod": "Af//////////////////////////////////////////////////////////////////////////////////////",
        "required_shares": 3,
        "shares": [
            "1-f8hn9k+6y2Pig5JDMYAvrcKclqarhbcD+Q3ufUbYTfEdi9nbN333x+DybUvBlKoFH9UL27D+YgoZ793Jl0ni2JY=",
            "2-AVDxEzg7RfAFgEnSkpfMO5wfHh9APcpCk0ifrfyvHiWmtBQ8aidVuvxnjfxX9Wm+Q/XF5aKWZHSrl/pbFl8NkxYI",
            "3-nd00KiQD0kk+hPEflhmIL0u5z/7pA9njUeugsp43uIT40VwQMems08gz4YrMuKEh5wTxjhKWnEWsVrFJuH1BHJA=",
            "4-ZozKzAn0ci8dNO3qLGgVZ0hvqOKtMnz0FPHGnxQlBovrwzjNVznNTgLkHORHgVKe85IvniWU2NhXBOBjo5js7C0=",
            "5-qv/XHe0Xz7ccWcjyWrfjRBU/qeuKVivFkbIfwhDmD7uM6dKhl0YcaxeermRlw9K7G22f0s9fKmOYBOhkIGCWhN8="
        ]
    }
]
KEY_NAMES: ['root_key_encryption', 'policy_encryption', 'key_ursa', 'key_major']

Formatted JSON (shares_of_keys_split) after reading from shares_of_keys_split.json:
[
    {
        "prime_mod": "Af//////////////////////////////////////////////////////////////////////////////////////",
        "required_shares": 3,
        "shares": [
            "1-AYcjQ2Y8CiXu6i9WkKSIXye0vpRVXsE5KXF5SES5+U+PLht/OAJhoH4Z1dOc8uKh/qWzRqDy0IfaQtydqO/vkpne",
            "2-AZtssC1fi7JqPzoilp+jALWoQDYpssmMa5g8yE/5xGy1zRZ2U+iQGsArEJKHKZ/PKYyOSDTiSI1+TQvAozw/cP+H",
            "3-Zw9/jqC5B6cyUJdFIohK4T/pF7BdTC76pn/hU/GRvdg/VRa3Fu3RLGYRcSHdcOq1GvU49QGaQ09P86AiFlD/ll8=",
            "4-AeoLsYn/kiWlw3K0nC04Pap7uTjpXkkg1pxCk1ChYUL2hNdgYY16w8LK2G9tDlX0oVDoGOFQxalNS5Q8JX4kPl5k",
            "5-JGFGH3wXDGXyoHqbv7LZEVuwmdS1wGH/eYTeRgky/BCdnVNTTDbyg1lljWi8TuzuLmbn+c/Kv3g/7ZStc7ktV5k="
        ]
    },
    {
        "prime_mod": "Af//////////////////////////////////////////////////////////////////////////////////////",
        "required_shares": 3,
        "shares": [
            "1-AfLvTtEOT1Q7k0K/HOHqN2iQdrciV/uxG5NyhxO071zRLfkzm3AupRGceEVuFoMrgrdgj0Caywc3bnIOj6biU0yP",
            "2-ARkvcdNMdkKTrYQUn+mcVdqdhYvwJQFDXCHzYRQ1ekZiiRI9TTBmxoeSzalH7ktnRYpNMzhf6q6T2EZMySZGZ69h",
            "3-AZz1nDnwqi0+svUyv01IwLtfXLKgyEYZ8d25x2W0A+/mRq9SRaXfxZIaN1/yuInmqaj8URuzwidLot4f3eKPcIym",
            "4-AX5BzgT66xQ8o5YZewzveArV/Cs0Qco03MbFuggwjFlcZtByhNCZojEytWludT6prxNt6OqWUXFezjmHzdu9beRf",
            "5-vRQHNGs4941/ZsjTKJB7yQFj9aqRjZQc3Rc4+6sTgsTpdZ4KsJRcZNxHxbskabBVyaH6pQeYjM1aWISZEdBftow="
        ]
    },
    {
        "prime_mod": "Af//////////////////////////////////////////////////////////////////////////////////////",
        "required_shares": 3,
        "shares": [
            "1-zF72YHE4f0WrohdRxzaVwPRj1Bwjsu5uCE+Xui2KKq20pt+jlu440hqlFuVYtYu13WJ8gllYYGLw0weLQFJrTts=",
            "2-AVHfwxLvFmOd2o4orV7e3n37+FG9SVtOCeQBBoAyQLbUE5I0eK7uf0hD0I7cdQI3A2MV8dzeaHQbE2+x/LxxQm3s",
            "3-Abrkx0isz94+8flrdwArQJpP8dwUoyqDNMt4fYI/U9zWfyZjtHhjC8Swt55IuEdoIcR+kUDIYJ2Mnws0tauMvZZq",
            "4-B24DAapk7yjx49+uqxu8FfBQcyIxII3uvrX8wFTDnLT3Y21W80veR2FaRSoihR8RAZxarhdA3LeTpY+2DaTcyFY=",
            "5-N3t2PefVllvaTYVUX7BQ8N0UFuXzPW43vbmEOnKP9m98SVFgH6j20FW4g4Czu1vRGm9OJMsJMZvxPsL94rmgA64="
        ]
    },
    {
        "prime_mod": "Af//////////////////////////////////////////////////////////////////////////////////////",
        "required_shares": 3,
        "shares": [
            "1-f8hn9k+6y2Pig5JDMYAvrcKclqarhbcD+Q3ufUbYTfEdi9nbN333x+DybUvBlKoFH9UL27D+YgoZ793Jl0ni2JY=",
            "2-AVDxEzg7RfAFgEnSkpfMO5wfHh9APcpCk0ifrfyvHiWmtBQ8aidVuvxnjfxX9Wm+Q/XF5aKWZHSrl/pbFl8NkxYI",
            "3-nd00KiQD0kk+hPEflhmIL0u5z/7pA9njUeugsp43uIT40VwQMems08gz4YrMuKEh5wTxjhKWnEWsVrFJuH1BHJA=",
            "4-ZozKzAn0ci8dNO3qLGgVZ0hvqOKtMnz0FPHGnxQlBovrwzjNVznNTgLkHORHgVKe85IvniWU2NhXBOBjo5js7C0=",
            "5-qv/XHe0Xz7ccWcjyWrfjRBU/qeuKVivFkbIfwhDmD7uM6dKhl0YcaxeermRlw9K7G22f0s9fKmOYBOhkIGCWhN8="
        ]
    }
]

Reconstructing key_0...
Reconstructed key_0: 39964b5303318f7ed23a35425a220fdbd1cdbbf2a4c99c4fd49322c1f731aded
Original key_0     : 39964b5303318f7ed23a35425a220fdbd1cdbbf2a4c99c4fd49322c1f731aded
Match: True

Reconstructing key_1...
Reconstructed key_1: 53365b6d12662ee8047a5c0279d2c325d50e7a0774e113a06e4dc16eae1dc3d2
Original key_1     : 53365b6d12662ee8047a5c0279d2c325d50e7a0774e113a06e4dc16eae1dc3d2
Match: True

Reconstructing key_2...
Reconstructed key_2: ba13616e57d92fc94c121da8d10108cbde50b8b556ccaf93d1190bd755a70897
Original key_2     : ba13616e57d92fc94c121da8d10108cbde50b8b556ccaf93d1190bd755a70897
Match: True

Reconstructing key_3...
Reconstructed key_3: c2dabdde201c5dd65622675c6b4ef1d584cbbc64a4f19dee2d9bdda279ca20d9
Original key_3     : c2dabdde201c5dd65622675c6b4ef1d584cbbc64a4f19dee2d9bdda279ca20d9
Match: True

Formatted JSON:
Key Name: root_key_encryption
Key Value: c2dabdde201c5dd65622675c6b4ef1d584cbbc64a4f19dee2d9bdda279ca20d9
Key Name: policy_encryption
Key Value: ba13616e57d92fc94c121da8d10108cbde50b8b556ccaf93d1190bd755a70897
Key Name: key_ursa
Key Value: 53365b6d12662ee8047a5c0279d2c325d50e7a0774e113a06e4dc16eae1dc3d2
Key Name: key_major
Key Value: 39964b5303318f7ed23a35425a220fdbd1cdbbf2a4c99c4fd49322c1f731aded
{
    "key_major": "39964b5303318f7ed23a35425a220fdbd1cdbbf2a4c99c4fd49322c1f731aded",
    "key_ursa": "53365b6d12662ee8047a5c0279d2c325d50e7a0774e113a06e4dc16eae1dc3d2",
    "policy_encryption": "ba13616e57d92fc94c121da8d10108cbde50b8b556ccaf93d1190bd755a70897",
    "root_key_encryption": "c2dabdde201c5dd65622675c6b4ef1d584cbbc64a4f19dee2d9bdda279ca20d9"
}

SHA256(Reconstructed JSON):
fc68cf1b4eda2d6b69181bb2916e0d9695771fc97e547271d9df4ff6fd4cd0b1

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