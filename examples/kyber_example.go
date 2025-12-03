package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/gaurav001/pqc-liboqs-go/pkg/pqc"
)

func main() {
	fmt.Println("Kyber768 Key Exchange Example\n")

	kem, err := pqc.NewKEM("Kyber768")
	if err != nil {
		log.Fatal(err)
	}
	defer kem.Close()

	publicKey, secretKey, err := kem.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Public key: %d bytes\n", len(publicKey))
	fmt.Printf("Secret key: %d bytes\n\n", len(secretKey))

	ciphertext, aliceSecret, err := kem.Encapsulate(publicKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Ciphertext: %d bytes\n", len(ciphertext))
	fmt.Printf("Alice secret: %s\n\n", hex.EncodeToString(aliceSecret))

	bobSecret, err := kem.Decapsulate(secretKey, ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Bob secret: %s\n\n", hex.EncodeToString(bobSecret))

	if bytes.Equal(aliceSecret, bobSecret) {
		fmt.Println("Success! Secrets match")
	} else {
		fmt.Println("Error! Secrets don't match")
	}
}
