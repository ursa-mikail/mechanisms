package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

func main() {
	fmt.Println("=== Ed25519 Key and Certificate ===")
	genEd25519()

	fmt.Println("\n=== ECDSA P-256 Key and Certificate ===")
	genECDSA()
}

func genEd25519() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Encode private key in PKCS#8 format
	privBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	privPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	fmt.Println(string(privPem))

	// Encode public key in PKIX format
	pubBytes, _ := x509.MarshalPKIXPublicKey(pub)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	fmt.Println(string(pubPem))

	// Generate self-signed certificate
	template := certTemplate()
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		panic(err)
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	fmt.Println(string(certPem))

	printCertDetails(certDER)
}

func genECDSA() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Marshal EC Private Key (SEC 1 format)
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	privPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	fmt.Println(string(privPem))

	// Marshal Public Key in PKIX format
	pubBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	fmt.Println(string(pubPem))

	// Generate self-signed certificate
	template := certTemplate()
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	fmt.Println(string(certPem))

	printCertDetails(certDER)
}

func certTemplate() *x509.Certificate {
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	return &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkixName(),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		IsCA:         true,
		BasicConstraintsValid: true,
	}
}

func pkixName() pkix.Name {
	return pkix.Name{
		CommonName:   "Test Cert",
		Organization: []string{"Example Org"},
		Country:      []string{"US"},
	}
}

func printCertDetails(der []byte) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Certificate Subject: %s\n", cert.Subject)
	fmt.Printf("Certificate Issuer : %s\n", cert.Issuer)
	fmt.Printf("Not Before         : %s\n", cert.NotBefore)
	fmt.Printf("Not After          : %s\n", cert.NotAfter)
	fmt.Printf("Serial Number      : %s\n", cert.SerialNumber)
	fmt.Printf("Is CA              : %v\n", cert.IsCA)
}

/*
=== Ed25519 Key and Certificate ===
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIM2vIOYW6wJ//0TdSWba02tcckFMu5//4CA4Z5ZZZPX
-----END PRIVATE KEY-----

-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA7Phv+RSBKOx8zLfRnlqJPwbv4TloBh28Lw56vXduN4A=
-----END PUBLIC KEY-----

-----BEGIN CERTIFICATE-----
MIIBZjCCARigAwIBAgIIJzir9cPyfIcwBQYDK2VwMDcxCzAJBgNVBAYTAlVTMRQw
EgYDVQQKEwtFeGFtcGxlIE9yZzESMBAGA1UEAxMJVGVzdCBDZXJ0MB4XDTA5MTEx
MDIzMDAwMFoXDTEwMTExMDIzMDAwMFowNzELMAkGA1UEBhMCVVMxFDASBgNVBAoT
C0V4YW1wbGUgT3JnMRIwEAYDVQQDEwlUZXN0IENlcnQwKjAFBgMrZXADIQDs+G/5
FIEo7HzMt9GeWok/Bu/hOWgGHbwvDnq9d243gKNCMEAwDgYDVR0PAQH/BAQDAgWg
MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFFc3xaRdUI81JONPlBNUZs9Sx645
MAUGAytlcANBAIFX+GjuzaoswSzihPoypdliUMkRPCxwk75ty7zhw63u+SNn1rPj
6lI3fWy+gflgni/HVLZCE7hpxApI9oKhRwg=
-----END CERTIFICATE-----

Certificate Subject: CN=Test Cert,O=Example Org,C=US
Certificate Issuer : CN=Test Cert,O=Example Org,C=US
Not Before         : 2009-11-10 23:00:00 +0000 UTC
Not After          : 2010-11-10 23:00:00 +0000 UTC
Serial Number      : 2826197838217772167
Is CA              : true

=== ECDSA P-256 Key and Certificate ===
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFm/QWbcGtpKmdS4HC9Ui4zIfQ3I+rP2D6oK9ha1PCQVoAoGCCqGSM49
AwEHoUQDQgAEhLK0yYASSDamVYXmZ6oSzZ1PQT4zqjnhjdyE6rtXrX+mxsdOL4IB
F+e9wYdi3bN4AVIA18g/2UlWfsXzB1P8cQ==
-----END EC PRIVATE KEY-----

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhLK0yYASSDamVYXmZ6oSzZ1PQT4z
qjnhjdyE6rtXrX+mxsdOL4IBF+e9wYdi3bN4AVIA18g/2UlWfsXzB1P8cQ==
-----END PUBLIC KEY-----

-----BEGIN CERTIFICATE-----
MIIBpjCCAUygAwIBAgIIEXhDozOPXuQwCgYIKoZIzj0EAwIwNzELMAkGA1UEBhMC
VVMxFDASBgNVBAoTC0V4YW1wbGUgT3JnMRIwEAYDVQQDEwlUZXN0IENlcnQwHhcN
MDkxMTEwMjMwMDAwWhcNMTAxMTEwMjMwMDAwWjA3MQswCQYDVQQGEwJVUzEUMBIG
A1UEChMLRXhhbXBsZSBPcmcxEjAQBgNVBAMTCVRlc3QgQ2VydDBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABISytMmAEkg2plWF5meqEs2dT0E+M6o54Y3chOq7V61/
psbHTi+CARfnvcGHYt2zeAFSANfIP9lJVn7F8wdT/HGjQjBAMA4GA1UdDwEB/wQE
AwIFoDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQK/3LQR1Hr3D+sLspUwF+X
CjlspDAKBggqhkjOPQQDAgNIADBFAiEAtoTeldTl6YWht+cRgY2GdFWF41+oLnZf
2/Q6kwkAZSACIFucPgqNf+vMER40UG6ZDDkfbxn42MogOwE029+bYJHW
-----END CERTIFICATE-----

Certificate Subject: CN=Test Cert,O=Example Org,C=US
Certificate Issuer : CN=Test Cert,O=Example Org,C=US
Not Before         : 2009-11-10 23:00:00 +0000 UTC
Not After          : 2010-11-10 23:00:00 +0000 UTC
Serial Number      : 1258830464073817828
Is CA              : true
*/