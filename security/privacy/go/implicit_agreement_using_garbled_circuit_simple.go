package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"golang.org/x/crypto/nacl/secretbox"
)

func generateKey() *[32]byte {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		log.Fatalf("Error generating key: %v", err)
	}
	return &key
}

func encrypt(key *[32]byte, message []byte) []byte {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		log.Fatalf("Error generating nonce: %v", err)
	}
	return append(nonce[:], secretbox.Seal(nil, message, &nonce, key)...)
}

func decrypt(key *[32]byte, cipher []byte) ([]byte, error) {
	var nonce [24]byte
	copy(nonce[:], cipher[:24])
	decrypted, ok := secretbox.Open(nil, cipher[24:], &nonce, key)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}
	return decrypted, nil
}

func evalLogic(a, b int, op string) int {
	switch op {
	case "a & b":
		return a & b
	case "a | b":
		return a | b
	case "a ^ b":
		return a ^ b
	case "~a":
		return ^a & 1
	default:
		log.Fatalf("Unsupported operator: %s", op)
	}
	return 0
}

func main() {
	operator := "a | b"
	x := 1
	y := 0

	fmt.Println("---Input parameters---")
	fmt.Println("Operation:", operator)
	fmt.Printf("Input: %d %d\n", x, y)

	keyX0 := generateKey()
	keyX1 := generateKey()
	keyY0 := generateKey()
	keyY1 := generateKey()

	data := []string{}
	for a := 0; a < 2; a++ {
		for b := 0; b < 2; b++ {
			result := evalLogic(a, b, operator)
			data = append(data, fmt.Sprintf("%d", result&0x01))
		}
	}
	fmt.Println("Outputs of function:", data)

	fmt.Println("\n---Keys generated---")
	fmt.Println("KeyX_0 (first 20 hex chars):", hex.EncodeToString(keyX0[:])[:20])
	fmt.Println("KeyX_1 (first 20 hex chars):", hex.EncodeToString(keyX1[:])[:20])
	fmt.Println("KeyY_0 (first 20 hex chars):", hex.EncodeToString(keyY0[:])[:20])
	fmt.Println("KeyY_1 (first 20 hex chars):", hex.EncodeToString(keyY1[:])[:20])

	fmt.Println("\n---Ciphers sent from Bob to Alice---")

	cipherText00 := encrypt(keyY0, encrypt(keyX0, []byte(data[0])))
	cipherText01 := encrypt(keyY0, encrypt(keyX1, []byte(data[1])))
	cipherText10 := encrypt(keyY1, encrypt(keyX0, []byte(data[2])))
	cipherText11 := encrypt(keyY1, encrypt(keyX1, []byte(data[3])))

	fmt.Println("Cipher (first 20 chars):", hex.EncodeToString(cipherText00)[:40])
	fmt.Println("Cipher (first 20 chars):", hex.EncodeToString(cipherText01)[:40])
	fmt.Println("Cipher (first 20 chars):", hex.EncodeToString(cipherText10)[:40])
	fmt.Println("Cipher (first 20 chars):", hex.EncodeToString(cipherText11)[:40])

	var keyB, keyA *[32]byte
	if x == 0 {
		keyB = keyX0
	} else {
		keyB = keyX1
	}

	if y == 0 {
		keyA = keyY0
	} else {
		keyA = keyY1
	}

	fmt.Println("\n---Bob and Alice's key---")
	fmt.Println("Bob's key:", hex.EncodeToString(keyB[:])[:20])
	fmt.Println("Alice's key:", hex.EncodeToString(keyA[:])[:20])

	fmt.Println("\n---Decrypt with keys (where '.' is an exception):")

	decryptTry := func(cipher []byte) {
		if inner, err := decrypt(keyA, cipher); err == nil {
			if outer, err := decrypt(keyB, inner); err == nil {
				fmt.Print(string(outer), " ")
				return
			}
		}
		fmt.Print(". ")
	}

	decryptTry(cipherText00)
	decryptTry(cipherText01)
	decryptTry(cipherText10)
	decryptTry(cipherText11)
	fmt.Println()
}

/*
% go mod tidy
% go run implicit_agreement_using_garbled_circuit_simple.go

---Input parameters---
Operation: a | b
Input: 1 0
Outputs of function: [0 1 1 1]

---Keys generated---
KeyX_0 (first 20 hex chars): 171672326d8ff6241f9a
KeyX_1 (first 20 hex chars): 0ff867e62672ab9f9a92
KeyY_0 (first 20 hex chars): 056783583debca6e45e3
KeyY_1 (first 20 hex chars): 59576e5c0f330bfddf6c

---Ciphers sent from Bob to Alice---
Cipher (first 20 chars): 4ee009feb70491c0b8fdd92fafee069f94cefae6
Cipher (first 20 chars): 29e66d2f3edf71a9c0f948e396f89416a3b110d7
Cipher (first 20 chars): 97e6ee744749ac4d6dd241e73ce06af9ef45376e
Cipher (first 20 chars): c133ff9425f4db365aa78ed9f50cd92dd299fcb2

---Bob and Alice's key---
Bob's key: 0ff867e62672ab9f9a92
Alice's key: 056783583debca6e45e3

---Decrypt with keys (where '.' is an exception):
. 1 . . 
*/