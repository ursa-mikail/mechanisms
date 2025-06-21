#!pip install pycryptodome libnum

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime
from Crypto.Random import get_random_bytes
import hashlib
import random
import libnum

# Parameters
n_choices = 5  # Number of outputs Bob can choose from
g = 2
bits = 128

# Generate prime modulus
p = getPrime(bits, randfunc=get_random_bytes)

# Alice's secret
a = random.randint(1, 2**64)

# Alice prepares n public values h_0 to h_(n-1)
h_list = [pow(g, random.randint(1, 2**64), p) for _ in range(n_choices)]

# Messages: model outputs (e.g., predictions)
messages = [f"Prediction for class {i}: confidence {random.randint(60, 99)}%" for i in range(n_choices)]
print("Available Predictions (hidden to Bob):")
for i, m in enumerate(messages):
    print(f"m[{i}] = {m}")

# Bob chooses an index privately
bob_index = int(input(f"\nBob: Choose index [0-{n_choices - 1}]: "))

# Bob's random secret
r = random.randint(1, 2**64)

# Bob computes T = g^r * h_i (mod p)
T = (pow(g, r, p) * h_list[bob_index]) % p

# Bob sends T to Alice (Bob does not send index!)

# Alice computes shared keys for all i:
# key_i = SHA256((T / h_i)^a mod p) = SHA256((g^r)^a) if i == bob_index
ciphertexts = []
for i in range(n_choices):
    inv_hi = libnum.invmod(h_list[i], p)
    shared = pow((T * inv_hi) % p, a, p)
    key_seed = (shared & 0xffffffffffffffff).to_bytes(16, 'big')
    key = hashlib.sha256(key_seed).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(messages[i].encode(), 16))
    ciphertexts.append(ct)

# Alice sends all ciphertexts to Bob
print("\nAlice sends all encrypted predictions to Bob.")

# Bob computes shared key = (g^a)^r = T^r (since only h_i cancels out)
shared = pow(g, a * r, p)
key_seed = (shared & 0xffffffffffffffff).to_bytes(16, 'big')
bob_key = hashlib.sha256(key_seed).digest()
cipher = AES.new(bob_key, AES.MODE_ECB)

# Bob tries decrypting only his chosen index
try:
    decrypted = unpad(cipher.decrypt(ciphertexts[bob_index]), 16).decode()
    print("\nBob decrypts only selected prediction:")
    print("Decrypted:", decrypted)
except Exception as e:
    print("Decryption failed:", str(e))

"""
Available Predictions (hidden to Bob):
m[0] = Prediction for class 0: confidence 98%
m[1] = Prediction for class 1: confidence 81%
m[2] = Prediction for class 2: confidence 64%
m[3] = Prediction for class 3: confidence 79%
m[4] = Prediction for class 4: confidence 77%

Bob: Choose index [0-4]: 4

Alice sends all encrypted predictions to Bob.

Bob decrypts only selected prediction:
Decrypted: Prediction for class 4: confidence 77%

# n_choices = 10  # Number of outputs Bob can choose from
Available Predictions (hidden to Bob):
m[0] = Prediction for class 0: confidence 61%
m[1] = Prediction for class 1: confidence 61%
m[2] = Prediction for class 2: confidence 72%
m[3] = Prediction for class 3: confidence 97%
m[4] = Prediction for class 4: confidence 65%
m[5] = Prediction for class 5: confidence 78%
m[6] = Prediction for class 6: confidence 60%
m[7] = Prediction for class 7: confidence 72%
m[8] = Prediction for class 8: confidence 91%
m[9] = Prediction for class 9: confidence 92%

Bob: Choose index [0-9]: 5

Alice sends all encrypted predictions to Bob.

Bob decrypts only selected prediction:
Decrypted: Prediction for class 5: confidence 78%
"""