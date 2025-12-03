package pqc

import (
	"fmt"
	"testing"
)

func TestMyKyber(t *testing.T) {
	fmt.Println("Testing Kyber...")
	kem, err := NewKEM("Kyber768")
	if err != nil {
		t.Fatal(err)
	}
	defer kem.Close()
	pk, sk, _ := kem.GenerateKeyPair()
	fmt.Printf("SUCCESS! PK=%d bytes, SK=%d bytes\n", len(pk), len(sk))
}
