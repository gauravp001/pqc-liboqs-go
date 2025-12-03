package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/gaurav001/pqc-liboqs-go/pkg/pqc"
)

func main() {
	fmt.Println("Dilithium3 Digital Signature Example\n")

	sig, err := pqc.NewSignature("ML-DSA-65")
	if err != nil {
		log.Fatal(err)
	}
	defer sig.Close()

	publicKey, secretKey, err := sig.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Public key: %d bytes\n", len(publicKey))
	fmt.Printf("Secret key: %d bytes\n\n", len(secretKey))

	message := []byte("Important message")
	signature, err := sig.Sign(message, secretKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Message: %s\n", string(message))
	fmt.Printf("Signature: %d bytes\n", len(signature))
	fmt.Printf("Sig hex: %s...\n\n", hex.EncodeToString(signature[:32]))

	err = sig.Verify(message, signature, publicKey)
	if err != nil {
		fmt.Println("Verification failed")
	} else {
		fmt.Println("Signature verified!")
	}

	tamperedMsg := []byte("Modified message")
	err = sig.Verify(tamperedMsg, signature, publicKey)
	if err != nil {
		fmt.Println("Tampered message rejected")
	}
}
