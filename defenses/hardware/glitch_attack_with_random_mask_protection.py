# Simulate a glitch attack during masked secure computation — and show why random masking protects against it
"""
Share the secrets (a and b) into two random parts.

Perform a secure masked AND (with fresh randomness).

Inject a glitch/fault (flip random bits during computation).

Compare whether the attacker can figure out the original secret.

✅ Even if attacker injects a glitch,
✅ They cannot learn anything about the real secret — because:
Randomness blinds the data.
Glitches just cause random wrong outputs, no useful information.
Fault detection or redundancy checks can catch it.

✅ If we detect mismatch or bad states → trigger a security reset, erase keys, alarm 🚨.

🛡️✨ In real systems (smartcards, secure chips):
- combine masking + redundancy.
- check parity, use time randomness, and trigger tamper alarms.
- re-randomize shares at each step!

"""
import random

def random_bit():
    return random.randint(0, 1)

def secure_masked_and_with_fault(a_shares, b_shares, inject_fault=False):
    a0, a1 = a_shares
    b0, b1 = b_shares

    r = random_bit()

    # Secure masked AND (before fault)
    c0 = (a0 & b0) ^ (a0 & b1) ^ (a1 & b0) ^ r
    c1 = (a1 & b1) ^ r

    if inject_fault:
        # 💥 Simulate a fault by flipping a random bit
        which_share = random.choice([0, 1])
        bit_to_flip = 1 << random.randint(0, 15)

        if which_share == 0:
            c0 ^= bit_to_flip
            print(f"💥 Fault injected: flipped bit {bin(bit_to_flip)} in c0!")
        else:
            c1 ^= bit_to_flip
            print(f"💥 Fault injected: flipped bit {bin(bit_to_flip)} in c1!")

    return (c0, c1)

def recombine_shares(shares):
    return shares[0] ^ shares[1]

def simulate_fault_attack(a, b, inject_fault=False):
    print(f"\n=== Masked AND Simulation with Fault Attack ===")
    print(f"Inputs: a = {hex(a)}, b = {hex(b)}, fault injected: {inject_fault}")

    # Step 1: Share secrets randomly
    a0 = random.randint(0, 1)
    a1 = a ^ a0
    b0 = random.randint(0, 1)
    b1 = b ^ b0

    print(f"Shares: a0={a0}, a1={a1}; b0={b0}, b1={b1}")

    # Step 2: Secure masked AND with optional fault
    c0, c1 = secure_masked_and_with_fault((a0, a1), (b0, b1), inject_fault=inject_fault)

    # Step 3: Recombine
    result_masked = recombine_shares((c0, c1))
    result_expected = a & b

    print(f"Result after masked AND: {result_masked} (expected: {result_expected})")

    if result_masked == result_expected:
        if inject_fault:
            print("⚠️ Fault injected but result remained correct — random luck!")
        else:
            print("✅ Correct result without attack.")
    else:
        print("⚡ Fault or attack detected! Result corrupted.")

# === Demo runs ===

# No attack
simulate_fault_attack(0x1, 0x1, inject_fault=False)

# Attack!
simulate_fault_attack(0x1, 0x1, inject_fault=True)

# Attack on other inputs
simulate_fault_attack(0x0, 0x1, inject_fault=True)
simulate_fault_attack(0x1, 0x0, inject_fault=True)
simulate_fault_attack(0x0, 0x0, inject_fault=True)

"""

=== Masked AND Simulation with Fault Attack ===
Inputs: a = 0x1, b = 0x1, fault injected: False
Shares: a0=0, a1=1; b0=1, b1=0
Result after masked AND: 1 (expected: 1)
✅ Correct result without attack.

=== Masked AND Simulation with Fault Attack ===
Inputs: a = 0x1, b = 0x1, fault injected: True
Shares: a0=1, a1=0; b0=1, b1=0
💥 Fault injected: flipped bit 0b1000000 in c0!
Result after masked AND: 65 (expected: 1)
⚡ Fault or attack detected! Result corrupted.

=== Masked AND Simulation with Fault Attack ===
Inputs: a = 0x0, b = 0x1, fault injected: True
Shares: a0=1, a1=1; b0=0, b1=1
💥 Fault injected: flipped bit 0b10000000000000 in c1!
Result after masked AND: 8192 (expected: 0)
⚡ Fault or attack detected! Result corrupted.

=== Masked AND Simulation with Fault Attack ===
Inputs: a = 0x1, b = 0x0, fault injected: True
Shares: a0=0, a1=1; b0=0, b1=0
💥 Fault injected: flipped bit 0b100000000000 in c0!
Result after masked AND: 2048 (expected: 0)
⚡ Fault or attack detected! Result corrupted.

=== Masked AND Simulation with Fault Attack ===
Inputs: a = 0x0, b = 0x0, fault injected: True
Shares: a0=0, a1=0; b0=0, b1=0
💥 Fault injected: flipped bit 0b1000000000000000 in c0!
Result after masked AND: 32768 (expected: 0)
⚡ Fault or attack detected! Result corrupted.
"""