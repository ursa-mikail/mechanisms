package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"time"
)

const secretKey = "supersecretkey" // Change this for security
const filePath = "signed_object.json"

type SignedObject struct {
	RandomHex    string `json:"random_hex"`
	StaticString string `json:"static_string"`
}

type StoredData struct {
	Object   SignedObject `json:"object"`
	Signature string      `json:"signature"`
}

func generateObject() SignedObject {
	rand.Seed(time.Now().UnixNano())
	randBytes := make([]byte, 16)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic(err)
	}

	return SignedObject{
		RandomHex:    hex.EncodeToString(randBytes),
		StaticString: "you should see this",
	}
}

func signObject(obj SignedObject) string {
	objJson, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}

	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write(objJson)
	return hex.EncodeToString(h.Sum(nil))
}

func storeObject(obj SignedObject, signature string) {
	data := StoredData{
		Object:   obj,
		Signature: signature,
	}

	file, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile(filePath, file, 0644)
	if err != nil {
		panic(err)
	}
}

func readObject() (SignedObject, string, error) {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return SignedObject{}, "", err
	}

	var data StoredData
	err = json.Unmarshal(file, &data)
	if err != nil {
		return SignedObject{}, "", err
	}

	return data.Object, data.Signature, nil
}

func verifyObject(obj SignedObject, signature string) bool {
	expectedSignature := signObject(obj)
	return hmac.Equal([]byte(expectedSignature), []byte(signature))
}

func main() {
	// Generate, sign, and store object
	obj := generateObject()
	signature := signObject(obj)
	storeObject(obj, signature)

	fmt.Println("Before object destruction:", obj)

	// Simulate object deletion
	var objDestroyed *SignedObject
	fmt.Println("After object destruction:", objDestroyed)

	// Read and verify object
	retrievedObj, retrievedSignature, err := readObject()
	if err != nil {
		fmt.Println("Error reading object:", err)
		return
	}

	if verifyObject(retrievedObj, retrievedSignature) {
		fmt.Println("Verification successful:", retrievedObj)
	} else {
		fmt.Println("Verification failed!")
	}
}

/*
Before object destruction: {e21ddc9250fc8f76f23fd30f8131c829 you should see this}
After object destruction: <nil>
Verification successful: {e21ddc9250fc8f76f23fd30f8131c829 you should see this}
*/