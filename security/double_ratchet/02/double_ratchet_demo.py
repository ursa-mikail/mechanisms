#!pip install pynacl

import os
import binascii
import hashlib
import hmac
from typing import Dict, Tuple
from nacl.public import PrivateKey, PublicKey, Box
from nacl.secret import SecretBox


class DoubleRatchet:
    """
    Simplified Double Ratchet Protocol Implementation
    
    This implements the Signal protocol's Double Ratchet algorithm with:
    - X3DH key agreement for initialization
    - Symmetric key ratcheting for message keys
    - Asymmetric DH ratcheting for forward secrecy
    """
    
    def __init__(self, name: str):
        self.name = name
        self.identity_key = PrivateKey.generate()
        
        # Core ratchet state
        self.root_key = None           # Shared secret that gets ratcheted
        self.send_chain_key = None     # Chain key for sending
        self.recv_chain_key = None     # Chain key for receiving
        
        # DH ratchet state
        self.my_ratchet_key = None     # Our current DH ratchet key pair
        self.their_ratchet_key = None  # Their current DH ratchet public key
        
        # Message counters
        self.send_count = 0
        self.recv_count = 0
        
        # Out-of-order message handling
        self.skipped_keys: Dict[Tuple[bytes, int], bytes] = {}
        
        # Ephemeral key for X3DH
        self.ephemeral_key = PrivateKey.generate()
    
    def get_public_bundle(self) -> dict:
        """Get public keys for key exchange"""
        return {
            'identity': self.identity_key.public_key.encode(),
            'ephemeral': self.ephemeral_key.public_key.encode()
        }
    
    # ==================== Key Derivation Functions ====================
    
    def _kdf_root(self, root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
        """
        Derive new root key and chain key from DH output.
        Uses HMAC-based key derivation.
        """
        # Extract pseudorandom key
        prk = hmac.new(root_key, dh_output, hashlib.sha256).digest()
        
        # Expand to root key and chain key
        new_root_key = hmac.new(prk, b"RootKey" + b'\x01', hashlib.sha256).digest()
        new_chain_key = hmac.new(prk, b"ChainKey" + b'\x01', hashlib.sha256).digest()
        
        return new_root_key, new_chain_key
    
    def _kdf_chain(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        """
        Derive next chain key and message key from current chain key.
        This is deterministic: same input always gives same output.
        """
        message_key = hmac.new(chain_key, b"MessageKey", hashlib.sha256).digest()
        next_chain_key = hmac.new(chain_key, b"NextChain", hashlib.sha256).digest()
        
        return next_chain_key, message_key
    
    # ==================== Session Initialization (X3DH) ====================
    
    def init_as_alice(self, bob_bundle: dict) -> bytes:
        """
        Initialize session as Alice (initiator).
        Returns Alice's ephemeral public key to send to Bob.
        """
        bob_identity = PublicKey(bob_bundle['identity'])
        bob_ephemeral = PublicKey(bob_bundle['ephemeral'])
        
        # Generate fresh ephemeral key for this session
        alice_ephemeral = PrivateKey.generate()
        
        # Perform 3-way Diffie-Hellman (X3DH)
        # DH1: Alice's identity with Bob's ephemeral
        dh1 = Box(self.identity_key, bob_ephemeral).shared_key()
        # DH2: Alice's ephemeral with Bob's identity
        dh2 = Box(alice_ephemeral, bob_identity).shared_key()
        # DH3: Alice's ephemeral with Bob's ephemeral
        dh3 = Box(alice_ephemeral, bob_ephemeral).shared_key()
        
        # Combine all DH outputs
        shared_secret = dh1 + dh2 + dh3
        
        # Derive initial root key
        self.root_key = hashlib.sha256(b"RootKey_" + shared_secret).digest()
        
        # Alice sends first message
        # Set up the initial ratchet keys
        self.my_ratchet_key = alice_ephemeral
        self.their_ratchet_key = bob_ephemeral
        
        # Derive Alice's sending chain from the initial DH
        dh_output = Box(self.my_ratchet_key, self.their_ratchet_key).shared_key()
        self.root_key, self.send_chain_key = self._kdf_root(self.root_key, dh_output)
        
        self._log(f"Session initialized as Alice")
        self._log(f"Root key: {self._hex(self.root_key)}")
        self._log(f"Send chain: {self._hex(self.send_chain_key)}")
        
        return alice_ephemeral.public_key.encode()
    
    def init_as_bob(self, alice_bundle: dict, alice_ephemeral_bytes: bytes):
        """Initialize session as Bob (responder)."""
        alice_identity = PublicKey(alice_bundle['identity'])
        alice_ephemeral = PublicKey(alice_ephemeral_bytes)
        
        # Perform same 3-way DH as Alice (same order!)
        # DH1: Bob's ephemeral with Alice's identity
        dh1 = Box(self.ephemeral_key, alice_identity).shared_key()
        # DH2: Bob's identity with Alice's ephemeral
        dh2 = Box(self.identity_key, alice_ephemeral).shared_key()
        # DH3: Bob's ephemeral with Alice's ephemeral
        dh3 = Box(self.ephemeral_key, alice_ephemeral).shared_key()
        
        # Same shared secret as Alice
        shared_secret = dh1 + dh2 + dh3
        
        # Same initial root key
        self.root_key = hashlib.sha256(b"RootKey_" + shared_secret).digest()
        
        # Bob receives Alice's first message
        self.their_ratchet_key = alice_ephemeral
        self.my_ratchet_key = self.ephemeral_key
        
        # Bob's receiving chain matches Alice's sending chain
        dh_output = Box(self.my_ratchet_key, self.their_ratchet_key).shared_key()
        self.root_key, self.recv_chain_key = self._kdf_root(self.root_key, dh_output)
        
        self._log(f"Session initialized as Bob")
        self._log(f"Root key: {self._hex(self.root_key)}")
        self._log(f"Recv chain: {self._hex(self.recv_chain_key)}")
    
    # ==================== Message Encryption/Decryption ====================
    
    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt a message."""
        if self.send_chain_key is None:
            # Need to initialize sending chain (happens for Bob's first send)
            self.my_ratchet_key = PrivateKey.generate()
            dh_output = Box(self.my_ratchet_key, self.their_ratchet_key).shared_key()
            self.root_key, self.send_chain_key = self._kdf_root(self.root_key, dh_output)
            self.send_count = 0
            self._log(f"Initialized send chain: {self._hex(self.send_chain_key)}")
        
        # Derive message key and advance chain
        self.send_chain_key, message_key = self._kdf_chain(self.send_chain_key)
        msg_num = self.send_count
        self.send_count += 1
        
        # Encrypt message
        box = SecretBox(message_key)
        ciphertext = box.encrypt(plaintext.encode())
        
        # Create header: [my_ratchet_public_key (32 bytes)][message_number (4 bytes)]
        header = self.my_ratchet_key.public_key.encode() + msg_num.to_bytes(4, 'big')
        
        self._log(f"📤 Sent message #{msg_num}, key: {self._hex(message_key)}")
        
        return header + ciphertext
    
    def decrypt(self, message: bytes) -> str:
        """Decrypt a message."""
        # Parse header
        sender_ratchet_key = PublicKey(message[:32])
        msg_num = int.from_bytes(message[32:36], 'big')
        ciphertext = message[36:]
        
        self._log(f"📥 Receiving message #{msg_num}")
        
        # Check if sender performed a DH ratchet
        if self.their_ratchet_key is None or sender_ratchet_key.encode() != self.their_ratchet_key.encode():
            self._perform_dh_ratchet(sender_ratchet_key)
        
        # Get the message key (handle out-of-order messages)
        message_key = self._get_message_key(sender_ratchet_key.encode(), msg_num)
        
        # Decrypt
        try:
            box = SecretBox(message_key)
            plaintext = box.decrypt(ciphertext)
            self._log(f"✅ Decrypted successfully, key: {self._hex(message_key)}")
            return plaintext.decode()
        except Exception as e:
            self._log(f"❌ Decryption failed: {e}")
            raise
    
    # ==================== DH Ratchet ====================
    
    def _perform_dh_ratchet(self, new_their_key: PublicKey):
        """Perform a DH ratchet step when receiving a new ratchet key."""
        self._log(f"🔄 Performing DH ratchet")
        
        # Update to their new ratchet key
        self.their_ratchet_key = new_their_key
        
        # Derive new receiving chain using our current ratchet key
        dh_output = Box(self.my_ratchet_key, self.their_ratchet_key).shared_key()
        self.root_key, self.recv_chain_key = self._kdf_root(self.root_key, dh_output)
        
        self.recv_count = 0
        
        self._log(f"New recv chain: {self._hex(self.recv_chain_key)}")
    
    def _get_message_key(self, ratchet_key: bytes, msg_num: int) -> bytes:
        """
        Get message key for a specific message number.
        Handles out-of-order delivery by storing skipped keys.
        """
        key_id = (ratchet_key, msg_num)
        
        # Check if we already computed this key (out-of-order message)
        if key_id in self.skipped_keys:
            self._log(f"Using stored key for message #{msg_num}")
            return self.skipped_keys.pop(key_id)
        
        # Advance chain to reach this message
        while self.recv_count < msg_num:
            self.recv_chain_key, skipped_key = self._kdf_chain(self.recv_chain_key)
            self.skipped_keys[(ratchet_key, self.recv_count)] = skipped_key
            self._log(f"Skipped message #{self.recv_count}, stored key")
            self.recv_count += 1
        
        # Derive the actual message key
        self.recv_chain_key, message_key = self._kdf_chain(self.recv_chain_key)
        self.recv_count += 1
        
        return message_key
    
    # ==================== Utilities ====================
    
    def _log(self, message: str):
        """Log a message with the participant's name."""
        print(f"{self.name}: {message}")
    
    def _hex(self, data: bytes, length: int = 4) -> str:
        """Convert bytes to hex string (first N bytes)."""
        return binascii.b2a_hex(data[:length]).decode() + "..."


# ==================== Test Suite ====================

def test_simple_conversation():
    """Test a simple back-and-forth conversation."""
    print("=" * 70)
    print("TEST: Simple Conversation")
    print("=" * 70)
    
    # Setup
    alice = DoubleRatchet("Alice")
    bob = DoubleRatchet("Bob")
    
    # Key exchange
    alice_bundle = alice.get_public_bundle()
    bob_bundle = bob.get_public_bundle()
    
    alice_ephemeral = alice.init_as_alice(bob_bundle)
    bob.init_as_bob(alice_bundle, alice_ephemeral)
    
    # Verify initial key agreement
    print(f"\n🔍 Verification:")
    print(f"Alice root key: {alice._hex(alice.root_key)}")
    print(f"Bob root key:   {bob._hex(bob.root_key)}")
    print(f"Root keys match: {alice.root_key == bob.root_key}")
    print(f"Alice send == Bob recv: {alice.send_chain_key == bob.recv_chain_key}")
    
    print("\n--- Conversation Start ---\n")
    
    # Alice -> Bob
    msg1 = "Hello Bob!"
    encrypted1 = alice.encrypt(msg1)
    decrypted1 = bob.decrypt(encrypted1)
    assert decrypted1 == msg1, f"Expected '{msg1}', got '{decrypted1}'"
    print(f"✅ Alice → Bob: '{msg1}'\n")
    
    # Bob -> Alice
    msg2 = "Hi Alice! How are you?"
    encrypted2 = bob.encrypt(msg2)
    decrypted2 = alice.decrypt(encrypted2)
    assert decrypted2 == msg2, f"Expected '{msg2}', got '{decrypted2}'"
    print(f"✅ Bob → Alice: '{msg2}'\n")
    
    # Alice -> Bob
    msg3 = "I'm great, thanks!"
    encrypted3 = alice.encrypt(msg3)
    decrypted3 = bob.decrypt(encrypted3)
    assert decrypted3 == msg3, f"Expected '{msg3}', got '{decrypted3}'"
    print(f"✅ Alice → Bob: '{msg3}'\n")
    
    print("🎉 Simple conversation test PASSED!\n")


def test_multiple_messages():
    """Test multiple consecutive messages from same sender."""
    print("=" * 70)
    print("TEST: Multiple Consecutive Messages")
    print("=" * 70)
    
    alice = DoubleRatchet("Alice")
    bob = DoubleRatchet("Bob")
    
    alice_bundle = alice.get_public_bundle()
    bob_bundle = bob.get_public_bundle()
    
    alice_ephemeral = alice.init_as_alice(bob_bundle)
    bob.init_as_bob(alice_bundle, alice_ephemeral)
    
    print("\n--- Alice sends 3 messages in a row ---\n")
    
    messages = ["Message 1", "Message 2", "Message 3"]
    encrypted_messages = [alice.encrypt(msg) for msg in messages]
    
    for i, (msg, enc) in enumerate(zip(messages, encrypted_messages), 1):
        dec = bob.decrypt(enc)
        assert dec == msg, f"Message {i} failed"
        print(f"✅ Message {i}: '{msg}'\n")
    
    print("🎉 Multiple messages test PASSED!\n")


def test_out_of_order():
    """Test out-of-order message delivery."""
    print("=" * 70)
    print("TEST: Out-of-Order Delivery")
    print("=" * 70)
    
    alice = DoubleRatchet("Alice")
    bob = DoubleRatchet("Bob")
    
    alice_bundle = alice.get_public_bundle()
    bob_bundle = bob.get_public_bundle()
    
    alice_ephemeral = alice.init_as_alice(bob_bundle)
    bob.init_as_bob(alice_bundle, alice_ephemeral)
    
    print("\n--- Alice sends 3 messages, Bob receives out of order ---\n")
    
    msg1 = alice.encrypt("First")
    msg2 = alice.encrypt("Second")
    msg3 = alice.encrypt("Third")
    
    # Receive out of order: 3, 1, 2
    dec3 = bob.decrypt(msg3)
    print(f"✅ Received message 3: '{dec3}'\n")
    assert dec3 == "Third"
    
    dec1 = bob.decrypt(msg1)
    print(f"✅ Received message 1: '{dec1}'\n")
    assert dec1 == "First"
    
    dec2 = bob.decrypt(msg2)
    print(f"✅ Received message 2: '{dec2}'\n")
    assert dec2 == "Second"
    
    print("🎉 Out-of-order test PASSED!\n")


if __name__ == "__main__":
    test_simple_conversation()
    test_multiple_messages()
    test_out_of_order()
    
    print("=" * 70)
    print("🎊 ALL TESTS PASSED! 🎊")
    print("=" * 70)

"""
======================================================================
TEST: Simple Conversation
======================================================================
Alice: Session initialized as Alice
Alice: Root key: 753ca6f2...
Alice: Send chain: 3d4efaef...
Bob: Session initialized as Bob
Bob: Root key: 753ca6f2...
Bob: Recv chain: 3d4efaef...

🔍 Verification:
Alice root key: 753ca6f2...
Bob root key:   753ca6f2...
Root keys match: True
Alice send == Bob recv: True

--- Conversation Start ---

Alice: 📤 Sent message #0, key: 330fdbe5...
Bob: 📥 Receiving message #0
Bob: ✅ Decrypted successfully, key: 330fdbe5...
✅ Alice → Bob: 'Hello Bob!'

Bob: Initialized send chain: d700cb14...
Bob: 📤 Sent message #0, key: 6b1b08dd...
Alice: 📥 Receiving message #0
Alice: 🔄 Performing DH ratchet
Alice: New recv chain: d700cb14...
Alice: ✅ Decrypted successfully, key: 6b1b08dd...
✅ Bob → Alice: 'Hi Alice! How are you?'

Alice: 📤 Sent message #1, key: ae64e7d9...
Bob: 📥 Receiving message #1
Bob: ✅ Decrypted successfully, key: ae64e7d9...
✅ Alice → Bob: 'I'm great, thanks!'

🎉 Simple conversation test PASSED!

======================================================================
TEST: Multiple Consecutive Messages
======================================================================
Alice: Session initialized as Alice
Alice: Root key: a7518a37...
Alice: Send chain: 2dc6e3d2...
Bob: Session initialized as Bob
Bob: Root key: a7518a37...
Bob: Recv chain: 2dc6e3d2...

--- Alice sends 3 messages in a row ---

Alice: 📤 Sent message #0, key: 0e915449...
Alice: 📤 Sent message #1, key: 3f671d26...
Alice: 📤 Sent message #2, key: 405841e7...
Bob: 📥 Receiving message #0
Bob: ✅ Decrypted successfully, key: 0e915449...
✅ Message 1: 'Message 1'

Bob: 📥 Receiving message #1
Bob: ✅ Decrypted successfully, key: 3f671d26...
✅ Message 2: 'Message 2'

Bob: 📥 Receiving message #2
Bob: ✅ Decrypted successfully, key: 405841e7...
✅ Message 3: 'Message 3'

🎉 Multiple messages test PASSED!

======================================================================
TEST: Out-of-Order Delivery
======================================================================
Alice: Session initialized as Alice
Alice: Root key: e5ccf07c...
Alice: Send chain: a7e16fa8...
Bob: Session initialized as Bob
Bob: Root key: e5ccf07c...
Bob: Recv chain: a7e16fa8...

--- Alice sends 3 messages, Bob receives out of order ---

Alice: 📤 Sent message #0, key: 55355bed...
Alice: 📤 Sent message #1, key: 7b9a3662...
Alice: 📤 Sent message #2, key: faa04391...
Bob: 📥 Receiving message #2
Bob: Skipped message #0, stored key
Bob: Skipped message #1, stored key
Bob: ✅ Decrypted successfully, key: faa04391...
✅ Received message 3: 'Third'

Bob: 📥 Receiving message #0
Bob: Using stored key for message #0
Bob: ✅ Decrypted successfully, key: 55355bed...
✅ Received message 1: 'First'

Bob: 📥 Receiving message #1
Bob: Using stored key for message #1
Bob: ✅ Decrypted successfully, key: 7b9a3662...
✅ Received message 2: 'Second'

🎉 Out-of-order test PASSED!

======================================================================
🎊 ALL TESTS PASSED! 🎊
======================================================================

"""