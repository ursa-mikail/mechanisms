# masked processing defense simulation
def simulate_masked_processing(result, mask_random, mask_static):
    print(f"\n=== Simulation for result = {hex(result)}, mask_random = {hex(mask_random)}, mask_static = {hex(mask_static)} ===")

    # Step 1: Combine the masks
    mask_combined = mask_random ^ mask_static
    print('mask_combined:', hex(mask_combined))

    # Step 2: Apply the mask to the result
    mask_resultant = result ^ mask_combined
    print('mask_resultant:', hex(mask_resultant))

    # Step 3: Remove the random mask
    mask_resultant_with_mask_random_removed = mask_resultant ^ mask_random
    print('mask_resultant_with_mask_random_removed:', hex(mask_resultant_with_mask_random_removed))

    # Step 4: Check if after unmasking, we get expected static mask (normal) or flipped one (suspicious)
    expected = mask_static
    if result == 1:
        expected ^= 0x1  # Flip the last bit for result = 1

    if mask_resultant_with_mask_random_removed != expected:
        print("⚡ Potential power attack detected! ⚡")
    else:
        print("✅ Masking/unmasking behavior normal.")

# Test cases
simulate_masked_processing(
    result=0x0, 
    mask_random=0xdeaf, 
    mask_static=0xa5a5
)

simulate_masked_processing(
    result=0x1, 
    mask_random=0xdeaf, 
    mask_static=0xa5a5
)

simulate_masked_processing(
    result=0x0, 
    mask_random=0xdeaf, 
    mask_static=0x5a5a
)

simulate_masked_processing(
    result=0x1, 
    mask_random=0xdeaf, 
    mask_static=0x5a5a
)

# double-masked processing defense simulation

def simulate_double_masked_processing(result, mask_random_1, mask_static_1, mask_random_2, mask_static_2):
    print(f"\n=== Simulation for result = {hex(result)} ===")
    print(f"Mask Set 1: mask_random_1 = {hex(mask_random_1)}, mask_static_1 = {hex(mask_static_1)}")
    print(f"Mask Set 2: mask_random_2 = {hex(mask_random_2)}, mask_static_2 = {hex(mask_static_2)}")

    # First masking path
    mask_combined_1 = mask_random_1 ^ mask_static_1
    mask_resultant_1 = result ^ mask_combined_1
    mask_resultant_unmasked_1 = mask_resultant_1 ^ mask_random_1

    # Second masking path
    mask_combined_2 = mask_random_2 ^ mask_static_2
    mask_resultant_2 = result ^ mask_combined_2
    mask_resultant_unmasked_2 = mask_resultant_2 ^ mask_random_2

    # Print for debugging
    print("\n-- Path 1 --")
    print('mask_combined_1:', hex(mask_combined_1))
    print('mask_resultant_1:', hex(mask_resultant_1))
    print('mask_resultant_unmasked_1:', hex(mask_resultant_unmasked_1))

    print("\n-- Path 2 --")
    print('mask_combined_2:', hex(mask_combined_2))
    print('mask_resultant_2:', hex(mask_resultant_2))
    print('mask_resultant_unmasked_2:', hex(mask_resultant_unmasked_2))

    # Check expected unmasked results
    expected_1 = mask_static_1
    expected_2 = mask_static_2

    if result == 1:
        expected_1 ^= 0x1
        expected_2 ^= 0x1

    # Verify both independently
    pass_1 = (mask_resultant_unmasked_1 == expected_1)
    pass_2 = (mask_resultant_unmasked_2 == expected_2)

    if pass_1 and pass_2:
        print("\n✅ Double masking/unmasking behavior normal.")
    else:
        print("\n⚡ Potential power attack or fault injection detected! ⚡")
        if not pass_1:
            print("⚠️ Path 1 failed verification.")
        if not pass_2:
            print("⚠️ Path 2 failed verification.")


# Example usage

simulate_double_masked_processing(
    result=0x0,
    mask_random_1=0xdeaf,
    mask_static_1=0xa5a5,
    mask_random_2=0xbeef,
    mask_static_2=0x5a5a
)

simulate_double_masked_processing(
    result=0x1,
    mask_random_1=0xdeaf,
    mask_static_1=0xa5a5,
    mask_random_2=0xbeef,
    mask_static_2=0x5a5a
)

# Simulate a fault attack (bit-flip, glitch, etc.) to see how your double-masking detects the corruption! 🚨

import random

# double-masked processing defense simulation with optional fault injection

def simulate_double_masked_processing(result, mask_random_1, mask_static_1, mask_random_2, mask_static_2, inject_fault=False):
    print(f"\n=== Simulation for result = {hex(result)} (fault injected: {inject_fault}) ===")
    print(f"Mask Set 1: mask_random_1 = {hex(mask_random_1)}, mask_static_1 = {hex(mask_static_1)}")
    print(f"Mask Set 2: mask_random_2 = {hex(mask_random_2)}, mask_static_2 = {hex(mask_static_2)}")

    # First masking path
    mask_combined_1 = mask_random_1 ^ mask_static_1
    mask_resultant_1 = result ^ mask_combined_1

    # Second masking path
    mask_combined_2 = mask_random_2 ^ mask_static_2
    mask_resultant_2 = result ^ mask_combined_2

    # Optional: inject a fault (flip a random bit)
    if inject_fault:
        bit_to_flip = 1 << random.randint(0, 15)  # assume 16-bit values
        print(f"\n💥 Fault injected: flipping bit {bin(bit_to_flip)} in path 2 masked result.")
        mask_resultant_2 ^= bit_to_flip

    # Unmask
    mask_resultant_unmasked_1 = mask_resultant_1 ^ mask_random_1
    mask_resultant_unmasked_2 = mask_resultant_2 ^ mask_random_2

    # Print for debugging
    print("\n-- Path 1 --")
    print('mask_combined_1:', hex(mask_combined_1))
    print('mask_resultant_1:', hex(mask_resultant_1))
    print('mask_resultant_unmasked_1:', hex(mask_resultant_unmasked_1))

    print("\n-- Path 2 --")
    print('mask_combined_2:', hex(mask_combined_2))
    print('mask_resultant_2:', hex(mask_resultant_2))
    print('mask_resultant_unmasked_2:', hex(mask_resultant_unmasked_2))

    # Expected unmasked result
    expected_1 = mask_static_1
    expected_2 = mask_static_2
    if result == 1:
        expected_1 ^= 0x1
        expected_2 ^= 0x1

    # Verify
    pass_1 = (mask_resultant_unmasked_1 == expected_1)
    pass_2 = (mask_resultant_unmasked_2 == expected_2)

    if pass_1 and pass_2:
        print("\n✅ Double masking/unmasking behavior normal.")
    else:
        print("\n⚡ Potential power attack or fault injection detected! ⚡")
        if not pass_1:
            print("⚠️ Path 1 failed verification.")
        if not pass_2:
            print("⚠️ Path 2 failed verification.")

# Example 1: Normal behavior (no attack)
simulate_double_masked_processing(
    result=0x0,
    mask_random_1=0xdeaf,
    mask_static_1=0xa5a5,
    mask_random_2=0xbeef,
    mask_static_2=0x5a5a,
    inject_fault=False
)

# Example 2: Fault injected (simulate attack)
simulate_double_masked_processing(
    result=0x0,
    mask_random_1=0xdeaf,
    mask_static_1=0xa5a5,
    mask_random_2=0xbeef,
    mask_static_2=0x5a5a,
    inject_fault=True
)

# Full masked share simulation, like a real formal countermeasure.
"""
Instead of just masking result, we split it into two shares:

share0 = random

share1 = result XOR share0

result = share0 XOR share1
👉 Operations are done separately on the shares!
👉 Faults must corrupt both shares together to succeed undetected (very unlikely).

"""

import random

def simulate_shared_masking(result, inject_fault=False):
    print(f"\n=== Shared Masking Simulation for result = {hex(result)} (fault injected: {inject_fault}) ===")

    # Step 1: Share splitting
    share0 = random.randint(0, 0xFFFF)  # 16-bit random value
    share1 = result ^ share0

    print(f"Initial shares: share0 = {hex(share0)}, share1 = {hex(share1)}")

    # Step 2: Fault Injection (optional)
    if inject_fault:
        # Flip a random bit in one of the shares
        which_share = random.choice([0, 1])
        bit_to_flip = 1 << random.randint(0, 15)

        if which_share == 0:
            share0 ^= bit_to_flip
            print(f"\n💥 Fault injected: flipped bit {bin(bit_to_flip)} in share0!")
        else:
            share1 ^= bit_to_flip
            print(f"\n💥 Fault injected: flipped bit {bin(bit_to_flip)} in share1!")

    # Step 3: Recombine the shares
    recombined_result = share0 ^ share1
    print(f"\nRecombined result: {hex(recombined_result)}")

    # Step 4: Verification
    if recombined_result == result:
        print("\n✅ Shares correctly recombined. No attack detected.")
    else:
        print("\n⚡ Attack or fault detected! ⚡ Shares don't recombine correctly.")

# Example 1: Normal processing (no attack)
simulate_shared_masking(
    result=0x0,
    inject_fault=False
)

# Example 2: Simulate fault (power glitch, bit-flip, etc.)
simulate_shared_masking(
    result=0x0,
    inject_fault=True
)

# You can also test with result = 0x1, or other secrets


"""
[Concept Explanation]
XOR random + static masks together to create a combined mask.

XOR the result (0 or 1) with the combined mask to produce a masked result.

To recover, remove the mask_random first.

If everything is perfect, you should get mask_static (for result 0) or mask_static ^ 0x1 (for result 1).

If not, something is leaking — maybe a power attack or glitch.

Concept of Double Masking:
With 2 independent masking operations.

Each operation must independently satisfy the correct unmasking.

If either fails → potential attack detected (like power glitch, fault injection, or side-channel attack).

This is stronger because attackers must break both independently masked paths at the same time — which is much harder.


=== Simulation for result = 0x0, mask_random = 0xdeaf, mask_static = 0xa5a5 ===
mask_combined: 0x7b0a
mask_resultant: 0x7b0a
mask_resultant_with_mask_random_removed: 0xa5a5
✅ Masking/unmasking behavior normal.

=== Simulation for result = 0x1, mask_random = 0xdeaf, mask_static = 0xa5a5 ===
mask_combined: 0x7b0a
mask_resultant: 0x7b0b
mask_resultant_with_mask_random_removed: 0xa5a4
✅ Masking/unmasking behavior normal.

=== Simulation for result = 0x0, mask_random = 0xdeaf, mask_static = 0x5a5a ===
mask_combined: 0x84f5
mask_resultant: 0x84f5
mask_resultant_with_mask_random_removed: 0x5a5a
✅ Masking/unmasking behavior normal.

=== Simulation for result = 0x1, mask_random = 0xdeaf, mask_static = 0x5a5a ===
mask_combined: 0x84f5
mask_resultant: 0x84f4
mask_resultant_with_mask_random_removed: 0x5a5b
✅ Masking/unmasking behavior normal.

=== Simulation for result = 0x0 ===
Mask Set 1: mask_random_1 = 0xdeaf, mask_static_1 = 0xa5a5
Mask Set 2: mask_random_2 = 0xbeef, mask_static_2 = 0x5a5a

-- Path 1 --
mask_combined_1: 0x7b0a
mask_resultant_1: 0x7b0a
mask_resultant_unmasked_1: 0xa5a5

-- Path 2 --
mask_combined_2: 0xe4b5
mask_resultant_2: 0xe4b5
mask_resultant_unmasked_2: 0x5a5a

✅ Double masking/unmasking behavior normal.

=== Simulation for result = 0x1 ===
Mask Set 1: mask_random_1 = 0xdeaf, mask_static_1 = 0xa5a5
Mask Set 2: mask_random_2 = 0xbeef, mask_static_2 = 0x5a5a

-- Path 1 --
mask_combined_1: 0x7b0a
mask_resultant_1: 0x7b0b
mask_resultant_unmasked_1: 0xa5a4

-- Path 2 --
mask_combined_2: 0xe4b5
mask_resultant_2: 0xe4b4
mask_resultant_unmasked_2: 0x5a5b

✅ Double masking/unmasking behavior normal.

# Double masking is robust:
Even if one path is corrupted → attack is caught immediately before any secret leaks out! 🔥

In normal mode, both masking paths work correctly → ✅ Normal.

In fault injection mode, we flip a random bit in the masked result (e.g., a bitflip from EM attack, laser, or voltage glitch) → ⚡ Attack detected!

=== Simulation for result = 0x0 (fault injected: False) ===
Mask Set 1: mask_random_1 = 0xdeaf, mask_static_1 = 0xa5a5
Mask Set 2: mask_random_2 = 0xbeef, mask_static_2 = 0x5a5a

-- Path 1 --
mask_combined_1: 0x7b0a
mask_resultant_1: 0x7b0a
mask_resultant_unmasked_1: 0xa5a5

-- Path 2 --
mask_combined_2: 0xe4b5
mask_resultant_2: 0xe4b5
mask_resultant_unmasked_2: 0x5a5a

✅ Double masking/unmasking behavior normal.

=== Simulation for result = 0x0 (fault injected: True) ===
Mask Set 1: mask_random_1 = 0xdeaf, mask_static_1 = 0xa5a5
Mask Set 2: mask_random_2 = 0xbeef, mask_static_2 = 0x5a5a

💥 Fault injected: flipping bit 0b100000 in path 2 masked result.

-- Path 1 --
mask_combined_1: 0x7b0a
mask_resultant_1: 0x7b0a
mask_resultant_unmasked_1: 0xa5a5

-- Path 2 --
mask_combined_2: 0xe4b5
mask_resultant_2: 0xe495
mask_resultant_unmasked_2: 0x5a7a

⚡ Potential power attack or fault injection detected! ⚡
⚠️ Path 2 failed verification.

#
=== Shared Masking Simulation for result = 0x0 (fault injected: False) ===
Initial shares: share0 = 0xc74d, share1 = 0xc74d

Recombined result: 0x0

✅ Shares correctly recombined. No attack detected.

=== Shared Masking Simulation for result = 0x0 (fault injected: True) ===
Initial shares: share0 = 0xf62c, share1 = 0xf62c

💥 Fault injected: flipped bit 0b10 in share0!

Recombined result: 0x2

⚡ Attack or fault detected! ⚡ Shares don't recombine correctly.


✅ Randomizes values everywhere in memory
✅ Even if one share is attacked, the system notices immediately
✅ Very lightweight (XOR and randomness)
✅ Easy to implement in embedded systems, crypto hardware, blockchain wallets, etc.

🧠 idea:
In real cryptographic defenses (like AES S-box masking), we also process on shares directly, like:

sbox(share0 XOR share1)  -->  sbox(share0) XOR sbox(share1)
(very simplified — but you get the drift).

Further: Full glitch-resistant crypto
➡️ To do basic masked logical operations (AND, OR) safely on shares 
➡️ With randomness in every step)

When you're working with shared masking (splitting secrets into share0, share1),
you need to be careful when performing operations like AND, OR, etc.
— because shares are random, and naïvely combining them can leak information.

Problem:
If you do normal AND, e.g.,

share0 & share1
then leakage can occur because the intermediate values correlate to the secret.

Solution: Use fresh randomness for every operation.
For example:
Masked AND between two secrets a and b (both masked as two shares):

Masked AND (secure) process:
Given:
a0, a1 are shares of a

b0, b1 are shares of b

Then, securely compute masked shares of a AND b as:

r = random_bit()
c0 = (a0 & b0) ^ (a0 & b1) ^ (a1 & b0) ^ r
c1 = (a1 & b1) ^ r
Result:

c0, c1 are the new shares of (a AND b)

"""

import random

def random_bit():
    return random.randint(0, 1)

def secure_masked_and(a_shares, b_shares):
    a0, a1 = a_shares
    b0, b1 = b_shares

    r = random_bit()

    c0 = (a0 & b0) ^ (a0 & b1) ^ (a1 & b0) ^ r
    c1 = (a1 & b1) ^ r

    return (c0, c1)

def recombine_shares(shares):
    return shares[0] ^ shares[1]

def simulate_masked_and(a, b):
    print(f"\n=== Masked AND Simulation ===")
    print(f"Inputs: a = {hex(a)}, b = {hex(b)}")

    # Step 1: Sharing
    a0 = random.randint(0, 1)
    a1 = a ^ a0
    b0 = random.randint(0, 1)
    b1 = b ^ b0

    print(f"Shares: a0={a0}, a1={a1}; b0={b0}, b1={b1}")

    # Step 2: Secure masked AND
    c0, c1 = secure_masked_and((a0, a1), (b0, b1))

    # Step 3: Recombine
    result_masked = recombine_shares((c0, c1))
    result_expected = a & b

    print(f"Masked AND result: {result_masked} (expected: {result_expected})")

    # Step 4: Verify
    if result_masked == result_expected:
        print("✅ Masked AND computed correctly!")
    else:
        print("❌ Error in masked AND computation!")

# Example Usage
simulate_masked_and(0x1, 0x1)  # 1 AND 1 => 1
simulate_masked_and(0x1, 0x0)  # 1 AND 0 => 0
simulate_masked_and(0x0, 0x1)  # 0 AND 1 => 0
simulate_masked_and(0x0, 0x0)  # 0 AND 0 => 0

"""
randomness r
✅ Even if attacker sees intermediate values (glitch, EM probe, DPA), he cannot infer anything useful, because the randomness blinds the computation

Step                    | Purpose
------------------------------------------------------------------------
Share splitting         | Hide secret with randomness
------------------------------------------------------------------------
Secure operations       | Perform AND/OR securely without leaking
------------------------------------------------------------------------
Fresh randomness in ops | Essential to avoid leakage during processing
------------------------------------------------------------------------

=== Masked AND Simulation ===
Inputs: a = 0x1, b = 0x1
Shares: a0=0, a1=1; b0=0, b1=1
Masked AND result: 1 (expected: 1)
✅ Masked AND computed correctly!

=== Masked AND Simulation ===
Inputs: a = 0x1, b = 0x0
Shares: a0=0, a1=1; b0=0, b1=0
Masked AND result: 0 (expected: 0)
✅ Masked AND computed correctly!

=== Masked AND Simulation ===
Inputs: a = 0x0, b = 0x1
Shares: a0=0, a1=0; b0=0, b1=1
Masked AND result: 0 (expected: 0)
✅ Masked AND computed correctly!

=== Masked AND Simulation ===
Inputs: a = 0x0, b = 0x0
Shares: a0=1, a1=1; b0=0, b1=0
Masked AND result: 0 (expected: 0)
✅ Masked AND computed correctly!
"""