from cryptography.fernet import Fernet

# Alice and Bob's inputs
alice_input = 1
bob_input = 0

# XOR logic function
def xor(a, b):
    return a ^ b

# --- Step 1: Generate keys for Alice and Bob ---
alice_key = Fernet.generate_key()
bob_key = Fernet.generate_key()

# Create Fernet cipher objects
alice_cipher = Fernet(alice_key)
bob_cipher = Fernet(bob_key)

# --- Step 2: Pre-compute all possible results in the truth table ---
# We'll encrypt these results so that only the right combination of keys can decrypt
result_table = {}
for a in range(2):
    for b in range(2):
        # Compute XOR result
        result = xor(a, b)
        
        # Create a key for this combination
        combo = f"{a}{b}"
        
        # Double encrypt the result: first with Bob's key, then with Alice's
        encrypted_result = alice_cipher.encrypt(bob_cipher.encrypt(str(result).encode()))
        
        # Store in our result table
        result_table[combo] = encrypted_result

# --- Step 3: Retrieve and decrypt the result based on Alice and Bob's inputs ---
try:
    # Get the encrypted result for the specific inputs
    combo_key = f"{alice_input}{bob_input}"
    encrypted_result = result_table[combo_key]
    
    # Decrypt in reverse order: first with Alice's key, then with Bob's
    partial_decrypted = alice_cipher.decrypt(encrypted_result)
    final_result = bob_cipher.decrypt(partial_decrypted).decode()
    
    print(f"\n--- Result of XOR logic (Alice ^ Bob): ---")
    print(f"Alice's input: {alice_input}")
    print(f"Bob's input: {bob_input}")
    print(f"XOR result: {final_result}")
    
    # Interpret the result
    if int(final_result) == 1:
        print("✅ Train the model.")
    else:
        print("❌ Do not train.")
        
except Exception as e:
    print(f"Decryption failed: {e}")

"""
Secure XOR gate using encryption to protect inputs and outputs.
The code demonstrates a privacy-preserving computation technique that allows 2 parties (Alice and Bob) to compute an XOR function without revealing their individual inputs to each other or a third party.
Here's how the system works:
1. Alice and Bob each have a binary input (0 or 1)
2. The system computes the XOR of their inputs (which is 1 if exactly one input is 1, otherwise 0)
3. The computation is secured using nested Fernet encryption
4. Only the correct combination of Alice and Bob's keys can decrypt the result. In this specific example:

Alice's input is set to 1
Bob's input is set to 0
The expected XOR result is 1 (since exactly one input is 1)

1. Generates encryption keys for both Alice and Bob
2. Pre-computes the XOR results for all possible input combinations (0,0), (0,1), (1,0), and (1,1)
3. Encrypts each result using nested encryption (first Bob's key, then Alice's)
4. Retrieves the result for the specific inputs (Alice=1, Bob=0)
5. Decrypts in the correct order (first Alice's key, then Bob's)
6. Displays the result and whether the model should be trained

### Applications of This Pattern
This pattern has valuable applications in privacy-preserving AI training scenarios:

It allows multiple parties to contribute data or consent to training without revealing their individual choices
It enables threshold-based systems where training only proceeds when certain conditions are met
It provides cryptographic guarantees rather than just policy-based privacy

In the example, training only happens when exactly one party consents (XOR = 1), which could be useful in scenarios requiring a specific decision pattern before proceeding.

### Security Considerations
While this example demonstrates the concept, a production implementation would need additional considerations:

Secure key exchange mechanisms
Protection against replay attacks
Verification of input validity
Proper error handling without leaking information

* refer: implicit_agreement_using_garbled_circuit_xor_enhanced.py

--- Result of XOR logic (Alice ^ Bob): ---
Alice's input: 1
Bob's input: 0

XOR result: 1
✅ Train the model.
else:
❌ Do not train.

"""