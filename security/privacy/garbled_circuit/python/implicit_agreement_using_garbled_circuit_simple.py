from cryptography.fernet import Fernet
import sys
import binascii

operator = "a & b"
x=1
y=1

operator=operator.replace('or','|')
operator=operator.replace('and','&')
operator=operator.replace('xor','^')
operator=operator.replace('not','~')

print("---Input parameters---")
print("Operation:",operator)
print("Input:",x,y)

# Bob created 4 keys for inputs for Alice and Bob
keyX_0 = Fernet.generate_key()
keyX_1 = Fernet.generate_key()
keyY_0 = Fernet.generate_key()
keyY_1 = Fernet.generate_key()

data =[]
for a in range(0,2):
	for b in range(0,2):
		data.append(str(eval(operator) & 0x01))
print("Outputs of function:",data)

print("\n---Keys generated---")

print("KeyX_0 (first 20 characters):",binascii.hexlify(bytearray(keyX_0))[:20])
print("KeyX_1 (first 20 characters):",binascii.hexlify(bytearray(keyX_1))[:20])
print("KeyY_0 (first 20 characters):",binascii.hexlify(bytearray(keyY_0))[:20])
print("KeyY_1 (first 20 characters):",binascii.hexlify(bytearray(keyY_1))[:20])

print("\n---Cipers send from Bob to Alice---")
cipher_text00 = Fernet(keyY_0).encrypt(Fernet(keyX_0).encrypt(data[0].encode()))
cipher_text01 = Fernet(keyY_0).encrypt(Fernet(keyX_1).encrypt(data[1].encode()))
cipher_text10 = Fernet(keyY_1).encrypt(Fernet(keyX_0).encrypt(data[2].encode()))
cipher_text11 = Fernet(keyY_1).encrypt(Fernet(keyX_1).encrypt(data[3].encode()))

print("Cipher (first 20 chars): ",binascii.hexlify(bytearray(cipher_text00))[:40])
print("Cipher (first 20 chars): ",binascii.hexlify(bytearray(cipher_text01))[:40])
print("Cipher (first 20 chars): ",binascii.hexlify(bytearray(cipher_text10))[:40])
print("Cipher (first 20 chars): ",binascii.hexlify(bytearray(cipher_text11))[:40])


if (x==0): keyB = keyX_0	# K(b=0)
if (x==1): keyB = keyX_1	# K(b=1)

if (y==0): keyA = keyY_0	# K(b=0)
if (y==1): keyA = keyY_1	# K(b=1)

print("\n---Bob and Alice's key---")
print("Bob's key: ",binascii.hexlify(bytearray(keyB))[:20])
print("Alice's key: ",binascii.hexlify(bytearray(keyA))[:20])

print("\n---Decrypt with keys (where '.' is an exception):")

# Bob passes the cipher_text values (cipher_text00 ... cipher_text11) to Alice, and provides the key for his input. If he says YES, he passes keyX_1, otherwise he will pass keyX_0.

# Alice receives the 4 values, and Bob's key. Now she uses oblivious transfer to gain the key for her answer. If she says YES, we obtain the key for keyY_1, without Bob knowing that he says YES. If she says NO, she gets keyY_0.
# Alice will have 2 keys and she tries all the ciphers:

try:
	print(Fernet(keyB).decrypt(Fernet(keyA).decrypt(cipher_text00)), end=' ')	
except:
	print(".", end=' ')
try:
	print(Fernet(keyB).decrypt(Fernet(keyA).decrypt(cipher_text01)), end=' ')	
except:
	print(".", end=' ')
try:
	print(Fernet(keyB).decrypt(Fernet(keyA).decrypt(cipher_text10)), end=' ')
except:
	print(".", end=' ')
try:
	print(Fernet(keyB).decrypt(Fernet(keyA).decrypt(cipher_text11)), end=' ')
except:
	print(".", end=' ')

"""
---Input parameters---
Operation: a & b
Input: 1 1
Outputs of function: ['0', '0', '0', '1']

---Keys generated---
KeyX_0 (first 20 characters): b'6c434934483155695369'
KeyX_1 (first 20 characters): b'5642474a566e74433574'
KeyY_0 (first 20 characters): b'5531354e34573032515f'
KeyY_1 (first 20 characters): b'4a386757523459444968'

---Cipers send from Bob to Alice---
Cipher (first 20 chars):  b'674141414141426f496b327a69584c6336364570'
Cipher (first 20 chars):  b'674141414141426f496b327a49477a5a64735245'
Cipher (first 20 chars):  b'674141414141426f496b327a73794a7168684335'
Cipher (first 20 chars):  b'674141414141426f496b327a42667079785a6173'

---Bob and Alice's key---
Bob's key:  b'5642474a566e74433574'
Alice's key:  b'4a386757523459444968'

---Decrypt with keys (where '.' is an exception):
. . . b'1' 
"""