package pqc

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestDilithium3Complete(t *testing.T) {
	line := strings.Repeat("=", 60)
	
	fmt.Println("\n" + line)
	fmt.Println("Testing COMPLETE ML-DSA-65 (Dilithium3) Digital Signature")
	fmt.Println(line)
	
	// Step 1: Create signature instance
	fmt.Println("\n[Step 1] Creating ML-DSA-65 signature instance...")
	sig, err := NewSignature("ML-DSA-65")
	if err != nil {
		t.Fatal("Failed to create signature:", err)
	}
	defer sig.Close()
	fmt.Println(" Signature instance created successfully")
	
	// Step 2: Generate signing keys
	fmt.Println("\n[Step 2] Generating signing key pair...")
	publicKey, secretKey, err := sig.GenerateKeyPair()
	if err != nil {
		t.Fatal("Failed to generate key pair:", err)
	}
	fmt.Printf(" Signing keys generated:\n")
	fmt.Printf("   - Public Key:  %d bytes\n", len(publicKey))
	fmt.Printf("   - Secret Key:  %d bytes\n", len(secretKey))
	fmt.Printf("   - PK preview: %s...\n", hex.EncodeToString(publicKey[:16]))
	
	// Step 3: Sign a message
	message := []byte("This is a test message for quantum-safe signing")
	fmt.Println("\n[Step 3] Signing message...")
	fmt.Printf("   Message: \"%s\"\n", string(message))
	signature, err := sig.Sign(message, secretKey)
	if err != nil {
		t.Fatal("Failed to sign message:", err)
	}
	fmt.Printf(" Message signed successfully:\n")
	fmt.Printf("   - Signature:   %d bytes\n", len(signature))
	fmt.Printf("   - Sig preview: %s...\n", hex.EncodeToString(signature[:16]))
	
	// Step 4: Verify signature (should pass)
	fmt.Println("\n[Step 4] Verifying signature with correct message...")
	err = sig.Verify(message, signature, publicKey)
	if err != nil {
		t.Fatal("Verification failed:", err)
	}
	fmt.Println(" Signature verified successfully!")
	fmt.Println("   ➜ Message is authentic")
	
	// Step 5: Test with tampered message (should fail)
	fmt.Println("\n[Step 5] Testing with tampered message (security check)...")
	tamperedMessage := []byte("This is a HACKED message")
	fmt.Printf("   Tampered: \"%s\"\n", string(tamperedMessage))
	err = sig.Verify(tamperedMessage, signature, publicKey)
	if err == nil {
		t.Fatal("SECURITY FAILURE: Tampered message was accepted!")
	}
	fmt.Println(" Tampered message correctly REJECTED")
	fmt.Println("   ➜ Security working properly")
	
	// Step 6: Test with wrong signature (should fail)
	fmt.Println("\n[Step 6] Testing with invalid signature (security check)...")
	wrongSignature := make([]byte, len(signature))
	copy(wrongSignature, signature)
	wrongSignature[0] ^= 0xFF
	err = sig.Verify(message, wrongSignature, publicKey)
	if err == nil {
		t.Fatal("SECURITY FAILURE: Invalid signature was accepted!")
	}
	fmt.Println(" Invalid signature correctly REJECTED")
	fmt.Println("   ➜ Security working properly")
	
	// Summary
	fmt.Println("\n" + line)
	fmt.Println(" ML-DSA-65 (DILITHIUM3) COMPLETE TEST PASSED!")
	fmt.Println(line)
	fmt.Println(" Key Generation:         WORKING")
	fmt.Println(" Message Signing:        WORKING")
	fmt.Println(" Signature Verification: WORKING")
	fmt.Println(" Tamper Detection:       WORKING")
	fmt.Println(" Security Validation:    WORKING")
	fmt.Println(" Quantum-Safe Signatures: COMPLETE")
	fmt.Println(line + "\n")
}
