package pqc

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestKyber768Complete(t *testing.T) {
	line := strings.Repeat("=", 60)
	
	fmt.Println("\n" + line)
	fmt.Println("Testing COMPLETE Kyber768 Key Exchange")
	fmt.Println(line)
	
	// Step 1: Create KEM instance
	fmt.Println("\n[Step 1] Creating Kyber768 KEM instance...")
	kem, err := NewKEM("Kyber768")
	if err != nil {
		t.Fatal("Failed to create KEM:", err)
	}
	defer kem.Close()
	fmt.Println("✅ KEM instance created successfully")
	
	// Step 2: Generate key pair
	fmt.Println("\n[Step 2] Generating key pair...")
	publicKey, secretKey, err := kem.GenerateKeyPair()
	if err != nil {
		t.Fatal("Failed to generate key pair:", err)
	}
	fmt.Printf("✅ Key pair generated:\n")
	fmt.Printf("   - Public Key:  %d bytes\n", len(publicKey))
	fmt.Printf("   - Secret Key:  %d bytes\n", len(secretKey))
	fmt.Printf("   - PK preview: %s...\n", hex.EncodeToString(publicKey[:16]))
	
	// Step 3: Encapsulate
	fmt.Println("\n[Step 3] Encapsulating (creating shared secret)...")
	ciphertext, sharedSecret1, err := kem.Encapsulate(publicKey)
	if err != nil {
		t.Fatal("Failed to encapsulate:", err)
	}
	fmt.Printf("✅ Encapsulation successful:\n")
	fmt.Printf("   - Ciphertext:     %d bytes\n", len(ciphertext))
	fmt.Printf("   - Shared Secret:  %d bytes\n", len(sharedSecret1))
	fmt.Printf("   - CT preview: %s...\n", hex.EncodeToString(ciphertext[:16]))
	fmt.Printf("   - SS preview: %s...\n", hex.EncodeToString(sharedSecret1[:16]))
	
	// Step 4: Decapsulate
	fmt.Println("\n[Step 4] Decapsulating (recovering shared secret)...")
	sharedSecret2, err := kem.Decapsulate(secretKey, ciphertext)
	if err != nil {
		t.Fatal("Failed to decapsulate:", err)
	}
	fmt.Printf("✅ Decapsulation successful:\n")
	fmt.Printf("   - Recovered Secret: %d bytes\n", len(sharedSecret2))
	fmt.Printf("   - SS preview: %s...\n", hex.EncodeToString(sharedSecret2[:16]))
	
	// Step 5: Verify secrets match
	fmt.Println("\n[Step 5] Verifying shared secrets match...")
	if !bytes.Equal(sharedSecret1, sharedSecret2) {
		t.Fatal("FAILURE: Shared secrets don't match!")
	}
	fmt.Println("✅ SUCCESS: Shared secrets are IDENTICAL!")
	fmt.Printf("   - Secret: %s\n", hex.EncodeToString(sharedSecret1))
	
	// Summary
	fmt.Println("\n" + line)
	fmt.Println("🎉 KYBER768 COMPLETE TEST PASSED!")
	fmt.Println(line)
	fmt.Println("✅ Key Generation:    WORKING")
	fmt.Println("✅ Encapsulation:     WORKING")
	fmt.Println("✅ Decapsulation:     WORKING")
	fmt.Println("✅ Secret Matching:   WORKING")
	fmt.Println("✅ Quantum-Safe Key Exchange: COMPLETE")
	fmt.Println(line + "\n")
}
