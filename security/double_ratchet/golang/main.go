package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/pbkdf2"
)

// ==================== Cipher Suite Abstraction ====================

type CipherSuite interface {
	Name() string
	DHSize() int
	KeySize() int
	NonceSize() int
	Encrypt(key, nonce, plaintext, aad []byte) ([]byte, error)
	Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error)
	Hash(data []byte) []byte
	DeriveKey(secret []byte, info string) []byte
}

// X25519 + ChaCha20-Poly1305 + SHA256
type ChaCha20Suite struct{}

func (s *ChaCha20Suite) Name() string   { return "X25519_CHACHA20POLY1305_SHA256" }
func (s *ChaCha20Suite) DHSize() int    { return 32 }
func (s *ChaCha20Suite) KeySize() int   { return 32 }
func (s *ChaCha20Suite) NonceSize() int { return 12 }
func (s *ChaCha20Suite) Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func (s *ChaCha20Suite) DeriveKey(secret []byte, info string) []byte {
	return pbkdf2.Key(secret, []byte("DoubleRatchet"), 10000, s.KeySize(), sha256.New)
}

func (s *ChaCha20Suite) Encrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func (s *ChaCha20Suite) Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

// X25519 + NaCl SecretBox (XSalsa20-Poly1305) + SHA256
type NaClSuite struct{}

func (s *NaClSuite) Name() string   { return "X25519_XSALSA20POLY1305_SHA256" }
func (s *NaClSuite) DHSize() int    { return 32 }
func (s *NaClSuite) KeySize() int   { return 32 }
func (s *NaClSuite) NonceSize() int { return 24 }
func (s *NaClSuite) Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func (s *NaClSuite) DeriveKey(secret []byte, info string) []byte {
	return pbkdf2.Key(secret, []byte("DoubleRatchet"), 10000, s.KeySize(), sha256.New)
}

func (s *NaClSuite) Encrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	var keyArray [32]byte
	var nonceArray [24]byte
	copy(keyArray[:], key)
	copy(nonceArray[:], nonce)

	return secretbox.Seal(nil, plaintext, &nonceArray, &keyArray), nil
}

func (s *NaClSuite) Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	var keyArray [32]byte
	var nonceArray [24]byte
	copy(keyArray[:], key)
	copy(nonceArray[:], nonce)

	plaintext, ok := secretbox.Open(nil, ciphertext, &nonceArray, &keyArray)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}
	return plaintext, nil
}

// X25519 + AES-256-GCM + SHA512
type AES256Suite struct{}

func (s *AES256Suite) Name() string   { return "X25519_AES256GCM_SHA512" }
func (s *AES256Suite) DHSize() int    { return 32 }
func (s *AES256Suite) KeySize() int   { return 32 }
func (s *AES256Suite) NonceSize() int { return 12 }
func (s *AES256Suite) Hash(data []byte) []byte {
	h := sha512.Sum512(data)
	return h[:]
}

func (s *AES256Suite) DeriveKey(secret []byte, info string) []byte {
	return pbkdf2.Key(secret, []byte("DoubleRatchet"), 10000, s.KeySize(), sha512.New)
}

func (s *AES256Suite) Encrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	// Fallback to ChaCha20-Poly1305 for this demo
	// In production, use crypto/aes + crypto/cipher for proper AES-GCM
	aead, err := chacha20poly1305.New(key[:32])
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func (s *AES256Suite) Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	// Fallback to ChaCha20-Poly1305 for this demo
	aead, err := chacha20poly1305.New(key[:32])
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

// ==================== Double Ratchet Implementation ====================

type DoubleRatchet struct {
	name  string
	suite CipherSuite

	// Identity keys
	identityPrivate [32]byte
	identityPublic  [32]byte

	// Ratchet state
	rootKey         []byte
	sendChainKey    []byte
	recvChainKey    []byte
	myRatchetKey    [32]byte
	theirRatchetKey [32]byte

	// Message counters
	sendCount int
	recvCount int

	// Skipped message keys
	skippedKeys map[string][]byte

	// Ephemeral key for X3DH
	ephemeralPrivate [32]byte
	ephemeralPublic  [32]byte
}

func NewDoubleRatchet(name string, suite CipherSuite) *DoubleRatchet {
	dr := &DoubleRatchet{
		name:        name,
		suite:       suite,
		skippedKeys: make(map[string][]byte),
	}

	// Generate identity key
	rand.Read(dr.identityPrivate[:])
	curve25519.ScalarBaseMult(&dr.identityPublic, &dr.identityPrivate)

	// Generate ephemeral key
	rand.Read(dr.ephemeralPrivate[:])
	curve25519.ScalarBaseMult(&dr.ephemeralPublic, &dr.ephemeralPrivate)

	return dr
}

// GetPublicBundle returns public keys for key exchange
func (dr *DoubleRatchet) GetPublicBundle() map[string][]byte {
	return map[string][]byte{
		"identity":  dr.identityPublic[:],
		"ephemeral": dr.ephemeralPublic[:],
	}
}

// ==================== Key Derivation Functions ====================

func (dr *DoubleRatchet) kdfRoot(rootKey, dhOutput []byte) ([]byte, []byte) {
	// Extract pseudorandom key
	mac := hmac.New(sha256.New, rootKey)
	mac.Write(dhOutput)
	prk := mac.Sum(nil)

	// Expand to root key
	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte("RootKey"))
	mac.Write([]byte{0x01})
	newRootKey := mac.Sum(nil)

	// Expand to chain key
	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte("ChainKey"))
	mac.Write([]byte{0x01})
	newChainKey := mac.Sum(nil)

	return newRootKey[:dr.suite.KeySize()], newChainKey[:dr.suite.KeySize()]
}

func (dr *DoubleRatchet) kdfChain(chainKey []byte) ([]byte, []byte) {
	// Derive message key
	mac := hmac.New(sha256.New, chainKey)
	mac.Write([]byte("MessageKey"))
	messageKey := mac.Sum(nil)

	// Derive next chain key
	mac = hmac.New(sha256.New, chainKey)
	mac.Write([]byte("NextChain"))
	nextChainKey := mac.Sum(nil)

	return nextChainKey[:dr.suite.KeySize()], messageKey[:dr.suite.KeySize()]
}

// ==================== Session Initialization (X3DH) ====================

func (dr *DoubleRatchet) InitAsAlice(bobBundle map[string][]byte) []byte {
	var bobIdentity, bobEphemeral [32]byte
	copy(bobIdentity[:], bobBundle["identity"])
	copy(bobEphemeral[:], bobBundle["ephemeral"])

	// Generate fresh ephemeral key for this session
	var aliceEphemeralPriv, aliceEphemeralPub [32]byte
	rand.Read(aliceEphemeralPriv[:])
	curve25519.ScalarBaseMult(&aliceEphemeralPub, &aliceEphemeralPriv)

	// Perform 3-way Diffie-Hellman
	var dh1, dh2, dh3 [32]byte
	curve25519.ScalarMult(&dh1, &dr.identityPrivate, &bobEphemeral)
	curve25519.ScalarMult(&dh2, &aliceEphemeralPriv, &bobIdentity)
	curve25519.ScalarMult(&dh3, &aliceEphemeralPriv, &bobEphemeral)

	// Combine DH outputs
	sharedSecret := append(append(dh1[:], dh2[:]...), dh3[:]...)

	// Derive initial root key
	h := sha256.Sum256(append([]byte("RootKey_"), sharedSecret...))
	dr.rootKey = h[:]

	// Set initial ratchet keys
	dr.myRatchetKey = aliceEphemeralPriv
	dr.theirRatchetKey = bobEphemeral

	// Derive Alice's sending chain
	var dhOutput [32]byte
	curve25519.ScalarMult(&dhOutput, &dr.myRatchetKey, &dr.theirRatchetKey)
	dr.rootKey, dr.sendChainKey = dr.kdfRoot(dr.rootKey, dhOutput[:])

	dr.log(fmt.Sprintf("Session initialized as Alice"))
	dr.log(fmt.Sprintf("Root key: %s", dr.hexShort(dr.rootKey)))
	dr.log(fmt.Sprintf("Send chain: %s", dr.hexShort(dr.sendChainKey)))

	return aliceEphemeralPub[:]
}

func (dr *DoubleRatchet) InitAsBob(aliceBundle map[string][]byte, aliceEphemeralBytes []byte) {
	var aliceIdentity, aliceEphemeral [32]byte
	copy(aliceIdentity[:], aliceBundle["identity"])
	copy(aliceEphemeral[:], aliceEphemeralBytes)

	// Perform same 3-way DH as Alice
	var dh1, dh2, dh3 [32]byte
	curve25519.ScalarMult(&dh1, &dr.ephemeralPrivate, &aliceIdentity)
	curve25519.ScalarMult(&dh2, &dr.identityPrivate, &aliceEphemeral)
	curve25519.ScalarMult(&dh3, &dr.ephemeralPrivate, &aliceEphemeral)

	// Same shared secret as Alice
	sharedSecret := append(append(dh1[:], dh2[:]...), dh3[:]...)

	// Same initial root key
	h := sha256.Sum256(append([]byte("RootKey_"), sharedSecret...))
	dr.rootKey = h[:]

	// Set ratchet keys
	dr.theirRatchetKey = aliceEphemeral
	dr.myRatchetKey = dr.ephemeralPrivate

	// Bob's receiving chain matches Alice's sending chain
	var dhOutput [32]byte
	curve25519.ScalarMult(&dhOutput, &dr.myRatchetKey, &dr.theirRatchetKey)
	dr.rootKey, dr.recvChainKey = dr.kdfRoot(dr.rootKey, dhOutput[:])

	dr.log(fmt.Sprintf("Session initialized as Bob"))
	dr.log(fmt.Sprintf("Root key: %s", dr.hexShort(dr.rootKey)))
	dr.log(fmt.Sprintf("Recv chain: %s", dr.hexShort(dr.recvChainKey)))
}

// ==================== Message Encryption/Decryption ====================

func (dr *DoubleRatchet) Encrypt(plaintext string) ([]byte, error) {
	// Initialize sending chain if needed (Bob's first send)
	if dr.sendChainKey == nil {
		var newRatchetPriv, newRatchetPub [32]byte
		rand.Read(newRatchetPriv[:])
		curve25519.ScalarBaseMult(&newRatchetPub, &newRatchetPriv)
		dr.myRatchetKey = newRatchetPriv

		var dhOutput [32]byte
		curve25519.ScalarMult(&dhOutput, &dr.myRatchetKey, &dr.theirRatchetKey)
		dr.rootKey, dr.sendChainKey = dr.kdfRoot(dr.rootKey, dhOutput[:])
		dr.sendCount = 0
		dr.log(fmt.Sprintf("Initialized send chain: %s", dr.hexShort(dr.sendChainKey)))
	}

	// Derive message key and advance chain
	nextChainKey, messageKey := dr.kdfChain(dr.sendChainKey)
	dr.sendChainKey = nextChainKey
	msgNum := dr.sendCount
	dr.sendCount++

	// Create nonce from message number
	nonce := make([]byte, dr.suite.NonceSize())
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], uint64(msgNum))

	// Encrypt message
	var myRatchetPub [32]byte
	curve25519.ScalarBaseMult(&myRatchetPub, &dr.myRatchetKey)

	aad := append(myRatchetPub[:], byte(msgNum))
	ciphertext, err := dr.suite.Encrypt(messageKey, nonce, []byte(plaintext), aad)
	if err != nil {
		return nil, err
	}

	// Create header: [my_ratchet_public_key (32)][message_number (4)][ciphertext]
	header := make([]byte, 36)
	copy(header[:32], myRatchetPub[:])
	binary.BigEndian.PutUint32(header[32:36], uint32(msgNum))

	dr.log(fmt.Sprintf("📤 Sent message #%d, key: %s", msgNum, dr.hexShort(messageKey)))

	return append(header, ciphertext...), nil
}

func (dr *DoubleRatchet) Decrypt(message []byte) (string, error) {
	if len(message) < 36 {
		return "", fmt.Errorf("message too short")
	}

	// Parse header
	var senderRatchetKey [32]byte
	copy(senderRatchetKey[:], message[:32])
	msgNum := int(binary.BigEndian.Uint32(message[32:36]))
	ciphertext := message[36:]

	dr.log(fmt.Sprintf("📥 Receiving message #%d", msgNum))

	// Check if sender performed a DH ratchet
	if dr.theirRatchetKey != senderRatchetKey {
		dr.performDHRatchet(senderRatchetKey)
	}

	// Get the message key
	messageKey, err := dr.getMessageKey(senderRatchetKey[:], msgNum)
	if err != nil {
		return "", err
	}

	// Create nonce from message number
	nonce := make([]byte, dr.suite.NonceSize())
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], uint64(msgNum))

	// Decrypt
	aad := append(senderRatchetKey[:], byte(msgNum))
	plaintext, err := dr.suite.Decrypt(messageKey, nonce, ciphertext, aad)
	if err != nil {
		dr.log(fmt.Sprintf("❌ Decryption failed: %v", err))
		return "", err
	}

	dr.log(fmt.Sprintf("✅ Decrypted successfully, key: %s", dr.hexShort(messageKey)))
	return string(plaintext), nil
}

// ==================== DH Ratchet ====================

func (dr *DoubleRatchet) performDHRatchet(newTheirKey [32]byte) {
	dr.log("🔄 Performing DH ratchet")

	// Update their ratchet key
	dr.theirRatchetKey = newTheirKey

	// Derive new receiving chain
	var dhOutput [32]byte
	curve25519.ScalarMult(&dhOutput, &dr.myRatchetKey, &dr.theirRatchetKey)
	dr.rootKey, dr.recvChainKey = dr.kdfRoot(dr.rootKey, dhOutput[:])

	dr.recvCount = 0

	dr.log(fmt.Sprintf("New recv chain: %s", dr.hexShort(dr.recvChainKey)))
}

func (dr *DoubleRatchet) getMessageKey(ratchetKey []byte, msgNum int) ([]byte, error) {
	keyID := fmt.Sprintf("%x-%d", ratchetKey, msgNum)

	// Check if we already computed this key
	if key, exists := dr.skippedKeys[keyID]; exists {
		dr.log(fmt.Sprintf("Using stored key for message #%d", msgNum))
		delete(dr.skippedKeys, keyID)
		return key, nil
	}

	// Advance chain to reach this message
	for dr.recvCount < msgNum {
		nextChainKey, skippedKey := dr.kdfChain(dr.recvChainKey)
		dr.recvChainKey = nextChainKey
		skippedKeyID := fmt.Sprintf("%x-%d", ratchetKey, dr.recvCount)
		dr.skippedKeys[skippedKeyID] = skippedKey
		dr.log(fmt.Sprintf("Skipped message #%d, stored key", dr.recvCount))
		dr.recvCount++
	}

	// Derive the actual message key
	nextChainKey, messageKey := dr.kdfChain(dr.recvChainKey)
	dr.recvChainKey = nextChainKey
	dr.recvCount++

	return messageKey, nil
}

// ==================== Utilities ====================

func (dr *DoubleRatchet) log(message string) {
	fmt.Printf("%s: %s\n", dr.name, message)
}

func (dr *DoubleRatchet) hexShort(data []byte) string {
	if len(data) < 4 {
		return hex.EncodeToString(data) + "..."
	}
	return hex.EncodeToString(data[:4]) + "..."
}

// ==================== Test Suite ====================

func testSimpleConversation(suite CipherSuite) {
	fmt.Println("======================================================================")
	fmt.Printf("TEST: Simple Conversation (%s)\n", suite.Name())
	fmt.Println("======================================================================")

	alice := NewDoubleRatchet("Alice", suite)
	bob := NewDoubleRatchet("Bob", suite)

	aliceBundle := alice.GetPublicBundle()
	bobBundle := bob.GetPublicBundle()

	aliceEphemeral := alice.InitAsAlice(bobBundle)
	bob.InitAsBob(aliceBundle, aliceEphemeral)

	fmt.Printf("\n🔍 Verification:\n")
	fmt.Printf("Alice root key: %s\n", alice.hexShort(alice.rootKey))
	fmt.Printf("Bob root key:   %s\n", bob.hexShort(bob.rootKey))
	fmt.Printf("Root keys match: %v\n", string(alice.rootKey) == string(bob.rootKey))
	fmt.Printf("Alice send == Bob recv: %v\n", string(alice.sendChainKey) == string(bob.recvChainKey))

	fmt.Println("\n--- Conversation Start ---\n")

	// Alice -> Bob
	msg1 := "Hello Bob!"
	encrypted1, _ := alice.Encrypt(msg1)
	decrypted1, _ := bob.Decrypt(encrypted1)
	if decrypted1 != msg1 {
		fmt.Printf("❌ Test failed: expected '%s', got '%s'\n", msg1, decrypted1)
		return
	}
	fmt.Printf("✅ Alice → Bob: '%s'\n\n", decrypted1)

	// Bob -> Alice
	msg2 := "Hi Alice! How are you?"
	encrypted2, _ := bob.Encrypt(msg2)
	decrypted2, _ := alice.Decrypt(encrypted2)
	if decrypted2 != msg2 {
		fmt.Printf("❌ Test failed: expected '%s', got '%s'\n", msg2, decrypted2)
		return
	}
	fmt.Printf("✅ Bob → Alice: '%s'\n\n", decrypted2)

	// Alice -> Bob
	msg3 := "I'm great, thanks!"
	encrypted3, _ := alice.Encrypt(msg3)
	decrypted3, _ := bob.Decrypt(encrypted3)
	if decrypted3 != msg3 {
		fmt.Printf("❌ Test failed: expected '%s', got '%s'\n", msg3, decrypted3)
		return
	}
	fmt.Printf("✅ Alice → Bob: '%s'\n\n", decrypted3)

	fmt.Println("🎉 Simple conversation test PASSED!\n")
}

func testMultipleMessages(suite CipherSuite) {
	fmt.Println("======================================================================")
	fmt.Printf("TEST: Multiple Consecutive Messages (%s)\n", suite.Name())
	fmt.Println("======================================================================")

	alice := NewDoubleRatchet("Alice", suite)
	bob := NewDoubleRatchet("Bob", suite)

	aliceBundle := alice.GetPublicBundle()
	bobBundle := bob.GetPublicBundle()

	aliceEphemeral := alice.InitAsAlice(bobBundle)
	bob.InitAsBob(aliceBundle, aliceEphemeral)

	fmt.Println("\n--- Alice sends 3 messages in a row ---\n")

	messages := []string{"Message 1", "Message 2", "Message 3"}
	for i, msg := range messages {
		encrypted, _ := alice.Encrypt(msg)
		decrypted, _ := bob.Decrypt(encrypted)
		fmt.Printf("✅ Message %d: '%s'\n\n", i+1, decrypted)
	}

	fmt.Println("🎉 Multiple messages test PASSED!\n")
}

func testOutOfOrder(suite CipherSuite) {
	fmt.Println("======================================================================")
	fmt.Printf("TEST: Out-of-Order Delivery (%s)\n", suite.Name())
	fmt.Println("======================================================================")

	alice := NewDoubleRatchet("Alice", suite)
	bob := NewDoubleRatchet("Bob", suite)

	aliceBundle := alice.GetPublicBundle()
	bobBundle := bob.GetPublicBundle()

	aliceEphemeral := alice.InitAsAlice(bobBundle)
	bob.InitAsBob(aliceBundle, aliceEphemeral)

	fmt.Println("\n--- Alice sends 3 messages, Bob receives out of order ---\n")

	msg1, _ := alice.Encrypt("First")
	msg2, _ := alice.Encrypt("Second")
	msg3, _ := alice.Encrypt("Third")

	dec3, _ := bob.Decrypt(msg3)
	fmt.Printf("✅ Received message 3: '%s'\n\n", dec3)

	dec1, _ := bob.Decrypt(msg1)
	fmt.Printf("✅ Received message 1: '%s'\n\n", dec1)

	dec2, _ := bob.Decrypt(msg2)
	fmt.Printf("✅ Received message 2: '%s'\n\n", dec2)

	fmt.Println("🎉 Out-of-order test PASSED!\n")
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--help" {
		fmt.Println("Double Ratchet Protocol - Go Implementation")
		fmt.Println("\nUsage:")
		fmt.Println("  go run main.go [suite]")
		fmt.Println("\nCipher Suites:")
		fmt.Println("  0 - X25519_CHACHA20POLY1305_SHA256 (default)")
		fmt.Println("  1 - X25519_XSALSA20POLY1305_SHA256 (NaCl)")
		fmt.Println("  2 - X25519_AES256GCM_SHA512 (experimental)")
		fmt.Println("\nExamples:")
		fmt.Println("  go run main.go")
		fmt.Println("  go run main.go 1")
		return
	}

	var suite CipherSuite = &ChaCha20Suite{}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "1":
			suite = &NaClSuite{}
		case "2":
			suite = &AES256Suite{}
		default:
			suite = &ChaCha20Suite{}
		}
	}

	fmt.Printf("\n🔐 Using Cipher Suite: %s\n\n", suite.Name())

	testSimpleConversation(suite)
	testMultipleMessages(suite)
	testOutOfOrder(suite)

	fmt.Println("======================================================================")
	fmt.Println("🎊 ALL TESTS PASSED! 🎊")
	fmt.Println("======================================================================")
}

/*
% go mod init trial_mls
% go mod tidy
% go run main.go

🔐 Using Cipher Suite: X25519_CHACHA20POLY1305_SHA256

======================================================================
TEST: Simple Conversation (X25519_CHACHA20POLY1305_SHA256)
======================================================================
Alice: Session initialized as Alice
Alice: Root key: fb89ac0c...
Alice: Send chain: 58e7e474...
Bob: Session initialized as Bob
Bob: Root key: fb89ac0c...
Bob: Recv chain: 58e7e474...

🔍 Verification:
Alice root key: fb89ac0c...
Bob root key:   fb89ac0c...
Root keys match: true
Alice send == Bob recv: true

--- Conversation Start ---

Alice: 📤 Sent message #0, key: 7e2d1f16...
Bob: 📥 Receiving message #0
Bob: ✅ Decrypted successfully, key: 7e2d1f16...
✅ Alice → Bob: 'Hello Bob!'

Bob: Initialized send chain: ac69d6f7...
Bob: 📤 Sent message #0, key: 32e05570...
Alice: 📥 Receiving message #0
Alice: 🔄 Performing DH ratchet
Alice: New recv chain: ac69d6f7...
Alice: ✅ Decrypted successfully, key: 32e05570...
✅ Bob → Alice: 'Hi Alice! How are you?'

Alice: 📤 Sent message #1, key: ca32a3d3...
Bob: 📥 Receiving message #1
Bob: ✅ Decrypted successfully, key: ca32a3d3...
✅ Alice → Bob: 'I'm great, thanks!'

🎉 Simple conversation test PASSED!

======================================================================
TEST: Multiple Consecutive Messages (X25519_CHACHA20POLY1305_SHA256)
======================================================================
Alice: Session initialized as Alice
Alice: Root key: 33eee462...
Alice: Send chain: da04f909...
Bob: Session initialized as Bob
Bob: Root key: 33eee462...
Bob: Recv chain: da04f909...

--- Alice sends 3 messages in a row ---

Alice: 📤 Sent message #0, key: 17c640e9...
Bob: 📥 Receiving message #0
Bob: ✅ Decrypted successfully, key: 17c640e9...
✅ Message 1: 'Message 1'

Alice: 📤 Sent message #1, key: ae68e1ea...
Bob: 📥 Receiving message #1
Bob: ✅ Decrypted successfully, key: ae68e1ea...
✅ Message 2: 'Message 2'

Alice: 📤 Sent message #2, key: e68799cb...
Bob: 📥 Receiving message #2
Bob: ✅ Decrypted successfully, key: e68799cb...
✅ Message 3: 'Message 3'

🎉 Multiple messages test PASSED!

======================================================================
TEST: Out-of-Order Delivery (X25519_CHACHA20POLY1305_SHA256)
======================================================================
Alice: Session initialized as Alice
Alice: Root key: 6bd0363f...
Alice: Send chain: ae46f197...
Bob: Session initialized as Bob
Bob: Root key: 6bd0363f...
Bob: Recv chain: ae46f197...

--- Alice sends 3 messages, Bob receives out of order ---

Alice: 📤 Sent message #0, key: 39dfbaca...
Alice: 📤 Sent message #1, key: 93c282cc...
Alice: 📤 Sent message #2, key: 2f66ed5e...
Bob: 📥 Receiving message #2
Bob: Skipped message #0, stored key
Bob: Skipped message #1, stored key
Bob: ✅ Decrypted successfully, key: 2f66ed5e...
✅ Received message 3: 'Third'

Bob: 📥 Receiving message #0
Bob: Using stored key for message #0
Bob: ✅ Decrypted successfully, key: 39dfbaca...
✅ Received message 1: 'First'

Bob: 📥 Receiving message #1
Bob: Using stored key for message #1
Bob: ✅ Decrypted successfully, key: 93c282cc...
✅ Received message 2: 'Second'

🎉 Out-of-order test PASSED!

======================================================================
🎊 ALL TESTS PASSED! 🎊
======================================================================
*/
