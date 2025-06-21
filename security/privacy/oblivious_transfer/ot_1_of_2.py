#!pip install pycryptodome libnum

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime
from Crypto.Random import get_random_bytes
import hashlib
import random
import libnum

# === PARAMETERS ===
g = 3
bits = 128

# Bob's choice (0 or 1): which model output he wants
# 0 = prediction for disease A
# 1 = prediction for disease B
bob_choice = int(input("Bob, choose which prediction you want (0 or 1): "))

# Generate a large prime for modulo operations
n = getPrime(bits, randfunc=get_random_bytes)

# Alice's random private key
a = random.randint(1, 2**64)
Alice_pub = pow(g, a, n)

# Alice computes two model predictions (m0, m1)
m0 = "@m0 Prediction: Disease A risk 10%"
m1 = "@m1 Prediction: Disease B risk 72%"

# Pad messages for AES encryption
m0_padded = pad(m0.encode(), 16)
m1_padded = pad(m1.encode(), 16)

# Bob's random secret
b = random.randint(1, 2**64)
if bob_choice == 0:
    Bob_pub = pow(g, b, n)
else:
    Bob_pub = (Alice_pub * pow(g, b, n)) % n

# Alice calculates inverse of her public key
inv_Alice_pub = libnum.invmod(Alice_pub, n)

# === Alice computes two symmetric AES keys ===
key0_seed = (pow(Bob_pub, a, n) & 0xffffffffffffffff).to_bytes(16, 'big')
key1_seed = (pow((Bob_pub * inv_Alice_pub) % n, a, n) & 0xffffffffffffffff).to_bytes(16, 'big')

key0 = hashlib.sha256(key0_seed).digest()
key1 = hashlib.sha256(key1_seed).digest()

# Alice encrypts both predictions
cipher0 = AES.new(key0, AES.MODE_ECB)
cipher1 = AES.new(key1, AES.MODE_ECB)

en_m0 = cipher0.encrypt(m0_padded)
en_m1 = cipher1.encrypt(m1_padded)

print("\n=== Alice sends encrypted model outputs ===")
print("Encrypted Output 0:", en_m0.hex())
print("Encrypted Output 1:", en_m1.hex())

# === Bob derives key and decrypts only one message ===
bob_key_seed = (pow(Alice_pub, b, n) & 0xffffffffffffffff).to_bytes(16, 'big')
bob_key = hashlib.sha256(bob_key_seed).digest()
cipher = AES.new(bob_key, AES.MODE_ECB)

# Bob tries decrypting both, but only one will succeed
print("\n=== Bob decrypts the selected prediction ===")
try:
    msg = unpad(cipher.decrypt(en_m0 if bob_choice == 0 else en_m1), 16)
    print("Decrypted Prediction:", msg.decode())
except Exception:
    print("Failed to decrypt selected message.")


"""
Bob, choose which prediction you want (0 or 1): 1

=== Alice sends encrypted model outputs ===
Encrypted Output 0: 3cb074fd59264cd155aa4ab2604cda564f4aee4841538a3c67d0dacc858d0c8578b1ee0d7a58c42db45c82ac26da9b7a
Encrypted Output 1: a209b57a4cee1d1c0706fa43b2b3f6c2d3c3d1e5351f6c8907074ce5cb519a06c613204432417eff856dc9f2c7ee4084

=== Bob decrypts the selected prediction ===
Decrypted Prediction: @m1 Prediction: Disease B risk 72%
"""