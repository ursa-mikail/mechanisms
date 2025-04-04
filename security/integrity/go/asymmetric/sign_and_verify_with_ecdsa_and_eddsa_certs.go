package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

func main() {
	// Clean up previous files
	os.Remove("ed25519_cert.pem")
	os.Remove("ed25519_priv.pem")
	os.Remove("ecdsa_cert.pem")
	os.Remove("ecdsa_priv.pem")

	// Generate keys and certs
	genAndDumpEd25519()
	genAndDumpECDSA()

	// Define the message
	message := []byte("sign this important message")

	fmt.Println("=== Signing & Verifying: Ed25519 ===")
	verifyEd25519(message)

	fmt.Println("\n=== Signing & Verifying: ECDSA ===")
	verifyECDSA(message)
}

// === Key & Cert Generation ===

func genAndDumpEd25519() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	template := certTemplate()
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, pub, priv)

	// Save cert
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	_ = ioutil.WriteFile("ed25519_cert.pem", certPEM, 0644)

	// Save private key
	privBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	_ = ioutil.WriteFile("ed25519_priv.pem", privPEM, 0644)
}

func genAndDumpECDSA() {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := certTemplate()
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)

	// Save cert
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	_ = ioutil.WriteFile("ecdsa_cert.pem", certPEM, 0644)

	// Save private key
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	_ = ioutil.WriteFile("ecdsa_priv.pem", privPEM, 0644)
}

// === Sign & Verify ===

func verifyEd25519(data []byte) {
	// Load private key
	privPemBytes, _ := ioutil.ReadFile("ed25519_priv.pem")
	privBlock, _ := pem.Decode(privPemBytes)
	privKeyRaw, _ := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	privKey := privKeyRaw.(ed25519.PrivateKey)

	// Load public key from cert
	certBytes, _ := ioutil.ReadFile("ed25519_cert.pem")
	certBlock, _ := pem.Decode(certBytes)
	cert, _ := x509.ParseCertificate(certBlock.Bytes)
	pubKey := cert.PublicKey.(ed25519.PublicKey)

	// Sign
	signature := ed25519.Sign(privKey, data)

	// Verify
	valid := ed25519.Verify(pubKey, data, signature)
	fmt.Printf("Ed25519 signature valid? %v\n", valid)
}

func verifyECDSA(data []byte) {
	hash := sha256.Sum256(data)

	// Load private key
	privPemBytes, _ := ioutil.ReadFile("ecdsa_priv.pem")
	privBlock, _ := pem.Decode(privPemBytes)
	privKey, _ := x509.ParseECPrivateKey(privBlock.Bytes)

	// Load public key from cert
	certBytes, _ := ioutil.ReadFile("ecdsa_cert.pem")
	certBlock, _ := pem.Decode(certBytes)
	cert, _ := x509.ParseCertificate(certBlock.Bytes)
	pubKey := cert.PublicKey.(*ecdsa.PublicKey)

	// Sign
	r, s, _ := ecdsa.Sign(rand.Reader, privKey, hash[:])

	// Verify
	valid := ecdsa.Verify(pubKey, hash[:], r, s)
	fmt.Printf("ECDSA signature valid? %v\n", valid)
}

// === Shared ===

func certTemplate() *x509.Certificate {
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkixName(),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
}

func pkixName() pkix.Name {
	return pkix.Name{
		CommonName:   "Self Signed Test",
		Organization: []string{"Example Org"},
		Country:      []string{"US"},
	}
}

/*
output certs:
ed25519_cert.pem
ed25519_priv.pem
ecdsa_cert.pem
ecdsa_priv.pem

=== Signing & Verifying: Ed25519 ===
Ed25519 signature valid? true

=== Signing & Verifying: ECDSA ===
ECDSA signature valid? true
*/