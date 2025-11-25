package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/pbkdf2"

	mls "github.com/cisco/go-mls"
)

// ==================== MLS Encryption Wrapper ====================

type MLSEncryptor struct {
	suite    mls.CipherSuite
	key      []byte
	nonce    []byte
	aad      []byte
	password string
	mode     string
}

func NewMLSEncryptor(password, mode string) *MLSEncryptor {
	e := &MLSEncryptor{
		password: password,
		mode:     mode,
		nonce:    make([]byte, 12), // 96-bit nonce
		aad:      []byte{0x00},
	}

	// Initialize based on mode
	switch mode {
	case "1":
		e.suite = mls.P256_AES128GCM_SHA256_P256
	case "2":
		e.suite = mls.X25519_CHACHA20POLY1305_SHA256_Ed25519
	case "3":
		e.suite = mls.P521_AES256GCM_SHA512_P521
	default:
		e.suite = mls.X25519_AES128GCM_SHA256_Ed25519
	}

	// Generate key from password
	salt := []byte("000000000000")
	keySize := 16 // default
	if mode == "2" || mode == "3" {
		keySize = 32
	}
	e.key = pbkdf2.Key([]byte(password), salt, 10000, keySize, sha256.New)

	// Zero nonce for demo
	for i := range e.nonce {
		e.nonce[i] = 0
	}

	return e
}

func (e *MLSEncryptor) Encrypt(message string) ([]byte, error) {
	aead, err := e.suite.NewAEAD(e.key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, e.nonce, []byte(message), e.aad), nil
}

func (e *MLSEncryptor) Decrypt(ciphertext []byte) (string, error) {
	aead, err := e.suite.NewAEAD(e.key)
	if err != nil {
		return "", err
	}
	plaintext, err := aead.Open(nil, e.nonce, ciphertext, e.aad)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (e *MLSEncryptor) String() string {
	return e.suite.String()
}

// ==================== Double Ratchet Implementation ====================

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

// ChaCha20-Poly1305 Suite
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

// Double Ratchet Protocol
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

func (dr *DoubleRatchet) GetPublicBundle() map[string][]byte {
	return map[string][]byte{
		"identity":  dr.identityPublic[:],
		"ephemeral": dr.ephemeralPublic[:],
	}
}

// Key Derivation Functions
func (dr *DoubleRatchet) kdfRoot(rootKey, dhOutput []byte) ([]byte, []byte) {
	mac := hmac.New(sha256.New, rootKey)
	mac.Write(dhOutput)
	prk := mac.Sum(nil)

	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte("RootKey"))
	mac.Write([]byte{0x01})
	newRootKey := mac.Sum(nil)

	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte("ChainKey"))
	mac.Write([]byte{0x01})
	newChainKey := mac.Sum(nil)

	return newRootKey[:dr.suite.KeySize()], newChainKey[:dr.suite.KeySize()]
}

func (dr *DoubleRatchet) kdfChain(chainKey []byte) ([]byte, []byte) {
	mac := hmac.New(sha256.New, chainKey)
	mac.Write([]byte("MessageKey"))
	messageKey := mac.Sum(nil)

	mac = hmac.New(sha256.New, chainKey)
	mac.Write([]byte("NextChain"))
	nextChainKey := mac.Sum(nil)

	return nextChainKey[:dr.suite.KeySize()], messageKey[:dr.suite.KeySize()]
}

// Session Initialization (X3DH)
func (dr *DoubleRatchet) InitAsAlice(bobBundle map[string][]byte) []byte {
	var bobIdentity, bobEphemeral [32]byte
	copy(bobIdentity[:], bobBundle["identity"])
	copy(bobEphemeral[:], bobBundle["ephemeral"])

	var aliceEphemeralPriv, aliceEphemeralPub [32]byte
	rand.Read(aliceEphemeralPriv[:])
	curve25519.ScalarBaseMult(&aliceEphemeralPub, &aliceEphemeralPriv)

	var dh1, dh2, dh3 [32]byte
	curve25519.ScalarMult(&dh1, &dr.identityPrivate, &bobEphemeral)
	curve25519.ScalarMult(&dh2, &aliceEphemeralPriv, &bobIdentity)
	curve25519.ScalarMult(&dh3, &aliceEphemeralPriv, &bobEphemeral)

	sharedSecret := append(append(dh1[:], dh2[:]...), dh3[:]...)
	h := sha256.Sum256(append([]byte("RootKey_"), sharedSecret...))
	dr.rootKey = h[:]

	dr.myRatchetKey = aliceEphemeralPriv
	dr.theirRatchetKey = bobEphemeral

	var dhOutput [32]byte
	curve25519.ScalarMult(&dhOutput, &dr.myRatchetKey, &dr.theirRatchetKey)
	dr.rootKey, dr.sendChainKey = dr.kdfRoot(dr.rootKey, dhOutput[:])

	dr.log(fmt.Sprintf("Session initialized as Alice"))
	dr.log(fmt.Sprintf("Root key: %s", dr.hexShort(dr.rootKey)))

	return aliceEphemeralPub[:]
}

func (dr *DoubleRatchet) InitAsBob(aliceBundle map[string][]byte, aliceEphemeralBytes []byte) {
	var aliceIdentity, aliceEphemeral [32]byte
	copy(aliceIdentity[:], aliceBundle["identity"])
	copy(aliceEphemeral[:], aliceEphemeralBytes)

	var dh1, dh2, dh3 [32]byte
	curve25519.ScalarMult(&dh1, &dr.ephemeralPrivate, &aliceIdentity)
	curve25519.ScalarMult(&dh2, &dr.identityPrivate, &aliceEphemeral)
	curve25519.ScalarMult(&dh3, &dr.ephemeralPrivate, &aliceEphemeral)

	sharedSecret := append(append(dh1[:], dh2[:]...), dh3[:]...)
	h := sha256.Sum256(append([]byte("RootKey_"), sharedSecret...))
	dr.rootKey = h[:]

	dr.theirRatchetKey = aliceEphemeral
	dr.myRatchetKey = dr.ephemeralPrivate

	var dhOutput [32]byte
	curve25519.ScalarMult(&dhOutput, &dr.myRatchetKey, &dr.theirRatchetKey)
	dr.rootKey, dr.recvChainKey = dr.kdfRoot(dr.rootKey, dhOutput[:])

	dr.log(fmt.Sprintf("Session initialized as Bob"))
	dr.log(fmt.Sprintf("Root key: %s", dr.hexShort(dr.rootKey)))
}

// Message Encryption/Decryption
func (dr *DoubleRatchet) Encrypt(plaintext string) ([]byte, error) {
	if dr.sendChainKey == nil {
		var newRatchetPriv, newRatchetPub [32]byte
		rand.Read(newRatchetPriv[:])
		curve25519.ScalarBaseMult(&newRatchetPub, &newRatchetPriv)
		dr.myRatchetKey = newRatchetPriv

		var dhOutput [32]byte
		curve25519.ScalarMult(&dhOutput, &dr.myRatchetKey, &dr.theirRatchetKey)
		dr.rootKey, dr.sendChainKey = dr.kdfRoot(dr.rootKey, dhOutput[:])
		dr.sendCount = 0
	}

	nextChainKey, messageKey := dr.kdfChain(dr.sendChainKey)
	dr.sendChainKey = nextChainKey
	msgNum := dr.sendCount
	dr.sendCount++

	nonce := make([]byte, dr.suite.NonceSize())
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], uint64(msgNum))

	var myRatchetPub [32]byte
	curve25519.ScalarBaseMult(&myRatchetPub, &dr.myRatchetKey)

	aad := append(myRatchetPub[:], byte(msgNum))
	ciphertext, err := dr.suite.Encrypt(messageKey, nonce, []byte(plaintext), aad)
	if err != nil {
		return nil, err
	}

	header := make([]byte, 36)
	copy(header[:32], myRatchetPub[:])
	binary.BigEndian.PutUint32(header[32:36], uint32(msgNum))

	dr.log(fmt.Sprintf("📤 Sent message #%d", msgNum))

	return append(header, ciphertext...), nil
}

func (dr *DoubleRatchet) Decrypt(message []byte) (string, error) {
	if len(message) < 36 {
		return "", fmt.Errorf("message too short")
	}

	var senderRatchetKey [32]byte
	copy(senderRatchetKey[:], message[:32])
	msgNum := int(binary.BigEndian.Uint32(message[32:36]))
	ciphertext := message[36:]

	dr.log(fmt.Sprintf("📥 Receiving message #%d", msgNum))

	if dr.theirRatchetKey != senderRatchetKey {
		dr.performDHRatchet(senderRatchetKey)
	}

	messageKey, err := dr.getMessageKey(senderRatchetKey[:], msgNum)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, dr.suite.NonceSize())
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], uint64(msgNum))

	aad := append(senderRatchetKey[:], byte(msgNum))
	plaintext, err := dr.suite.Decrypt(messageKey, nonce, ciphertext, aad)
	if err != nil {
		return "", err
	}

	dr.log(fmt.Sprintf("✅ Decrypted successfully"))
	return string(plaintext), nil
}

func (dr *DoubleRatchet) performDHRatchet(newTheirKey [32]byte) {
	dr.log("🔄 Performing DH ratchet")
	dr.theirRatchetKey = newTheirKey

	var dhOutput [32]byte
	curve25519.ScalarMult(&dhOutput, &dr.myRatchetKey, &dr.theirRatchetKey)
	dr.rootKey, dr.recvChainKey = dr.kdfRoot(dr.rootKey, dhOutput[:])
	dr.recvCount = 0
}

func (dr *DoubleRatchet) getMessageKey(ratchetKey []byte, msgNum int) ([]byte, error) {
	keyID := fmt.Sprintf("%x-%d", ratchetKey, msgNum)

	if key, exists := dr.skippedKeys[keyID]; exists {
		delete(dr.skippedKeys, keyID)
		return key, nil
	}

	for dr.recvCount < msgNum {
		nextChainKey, skippedKey := dr.kdfChain(dr.recvChainKey)
		dr.recvChainKey = nextChainKey
		skippedKeyID := fmt.Sprintf("%x-%d", ratchetKey, dr.recvCount)
		dr.skippedKeys[skippedKeyID] = skippedKey
		dr.recvCount++
	}

	nextChainKey, messageKey := dr.kdfChain(dr.recvChainKey)
	dr.recvChainKey = nextChainKey
	dr.recvCount++

	return messageKey, nil
}

func (dr *DoubleRatchet) log(message string) {
	fmt.Printf("%s: %s\n", dr.name, message)
}

func (dr *DoubleRatchet) hexShort(data []byte) string {
	if len(data) < 4 {
		return hex.EncodeToString(data)
	}
	return hex.EncodeToString(data[:4]) + "..."
}

// ==================== Demo Functions ====================

func demoMLSEncryption() {
	fmt.Println("\n")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("MLS STYLE ENCRYPTION DEMO")
	fmt.Println(strings.Repeat("=", 60))

	message := "Hello MLS World!"
	password := "securepassword"

	if len(os.Args) > 1 {
		message = os.Args[1]
	}
	if len(os.Args) > 2 {
		password = os.Args[2]
	}

	modes := []string{"0", "1", "2", "3"}
	modeNames := []string{
		"X25519_AES128GCM_SHA256_Ed25519",
		"P256_AES128GCM_SHA256_P256",
		"X25519_CHACHA20POLY1305_SHA256_Ed25519",
		"P521_AES256GCM_SHA512_P521",
	}

	for i, mode := range modes {
		encryptor := NewMLSEncryptor(password, mode)

		ciphertext, err := encryptor.Encrypt(message)
		if err != nil {
			fmt.Printf("❌ Encryption failed for %s: %v\n", modeNames[i], err)
			continue
		}

		decrypted, err := encryptor.Decrypt(ciphertext)
		if err != nil {
			fmt.Printf("❌ Decryption failed for %s: %v\n", modeNames[i], err)
			continue
		}

		fmt.Printf("\n🔐 Suite: %s\n", encryptor.String())
		fmt.Printf("Message:    '%s'\n", message)
		fmt.Printf("Password:   '%s'\n", password)
		fmt.Printf("Encrypted:  %x...\n", ciphertext[:16])
		fmt.Printf("Decrypted:  '%s'\n", decrypted)
		fmt.Printf("Status:     ✅ SUCCESS\n")
	}
}

func demoDoubleRatchet() {
	fmt.Println("\n")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("DOUBLE RATCHET PROTOCOL DEMO")
	fmt.Println(strings.Repeat("=", 60))

	suite := &ChaCha20Suite{}

	alice := NewDoubleRatchet("Alice", suite)
	bob := NewDoubleRatchet("Bob", suite)

	aliceBundle := alice.GetPublicBundle()
	bobBundle := bob.GetPublicBundle()

	aliceEphemeral := alice.InitAsAlice(bobBundle)
	bob.InitAsBob(aliceBundle, aliceEphemeral)

	fmt.Println("\n--- Secure Conversation ---")

	// Alice -> Bob
	msg1 := "Hello Bob, this is Alice!"
	encrypted1, _ := alice.Encrypt(msg1)
	decrypted1, _ := bob.Decrypt(encrypted1)
	fmt.Printf("✅ Alice → Bob: '%s'\n", decrypted1)

	// Bob -> Alice
	msg2 := "Hi Alice! Nice to meet you securely!"
	encrypted2, _ := bob.Encrypt(msg2)
	decrypted2, _ := alice.Decrypt(encrypted2)
	fmt.Printf("✅ Bob → Alice: '%s'\n", decrypted2)

	// Alice -> Bob
	msg3 := "Let's use forward secrecy!"
	encrypted3, _ := alice.Encrypt(msg3)
	decrypted3, _ := bob.Decrypt(encrypted3)
	fmt.Printf("✅ Alice → Bob: '%s'\n", decrypted3)

	fmt.Printf("\n🎉 Double Ratchet demo completed successfully!\n")
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--help" {
		fmt.Println("Secure Messaging Demo - MLS + Double Ratchet")
		fmt.Println("\nUsage:")
		fmt.Println("  go run main.go [message] [password]")
		fmt.Println("\nExamples:")
		fmt.Println("  go run main.go")
		fmt.Println("  go run main.go \"Hello World\" \"mypassword\"")
		return
	}

	fmt.Println("🚀 SECURE MESSAGING PROTOCOLS DEMONSTRATION")
	fmt.Println("This demo shows both MLS-style encryption and Double Ratchet protocol")

	demoMLSEncryption()
	demoDoubleRatchet()

	fmt.Println("\n")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("🎊 DEMONSTRATION COMPLETED! 🎊")
	fmt.Println(strings.Repeat("=", 60))
}

/*
% go mod init trial_mls
% go mod tidy
% go run main.go

🚀 SECURE MESSAGING PROTOCOLS DEMONSTRATION
This demo shows both MLS-style encryption and Double Ratchet protocol


============================================================
MLS STYLE ENCRYPTION DEMO
============================================================

🔐 Suite: X25519_AES128GCM_SHA256_Ed25519
Message:    'Hello MLS World!'
Password:   'securepassword'
Encrypted:  3de6e6075f11fff9394fe72be5db7f20...
Decrypted:  'Hello MLS World!'
Status:     ✅ SUCCESS

🔐 Suite: P256_AES128GCM_SHA256_P256
Message:    'Hello MLS World!'
Password:   'securepassword'
Encrypted:  3de6e6075f11fff9394fe72be5db7f20...
Decrypted:  'Hello MLS World!'
Status:     ✅ SUCCESS

🔐 Suite: X25519_CHACHA20POLY1305_SHA256_Ed25519
Message:    'Hello MLS World!'
Password:   'securepassword'
Encrypted:  f62b66e23b928935d5a4079e1ab449f9...
Decrypted:  'Hello MLS World!'
Status:     ✅ SUCCESS

🔐 Suite: P521_AES256GCM_SHA512_P521
Message:    'Hello MLS World!'
Password:   'securepassword'
Encrypted:  4b7ff30cbc82f1c5373a36c013d0f4d1...
Decrypted:  'Hello MLS World!'
Status:     ✅ SUCCESS


============================================================
DOUBLE RATCHET PROTOCOL DEMO
============================================================
Alice: Session initialized as Alice
Alice: Root key: 0f5957e0...
Bob: Session initialized as Bob
Bob: Root key: 0f5957e0...

--- Secure Conversation ---
Alice: 📤 Sent message #0
Bob: 📥 Receiving message #0
Bob: ✅ Decrypted successfully
✅ Alice → Bob: 'Hello Bob, this is Alice!'
Bob: 📤 Sent message #0
Alice: 📥 Receiving message #0
Alice: 🔄 Performing DH ratchet
Alice: ✅ Decrypted successfully
✅ Bob → Alice: 'Hi Alice! Nice to meet you securely!'
Alice: 📤 Sent message #1
Bob: 📥 Receiving message #1
Bob: ✅ Decrypted successfully
✅ Alice → Bob: 'Let's use forward secrecy!'

🎉 Double Ratchet demo completed successfully!


============================================================
🎊 DEMONSTRATION COMPLETED! 🎊
============================================================
*/
