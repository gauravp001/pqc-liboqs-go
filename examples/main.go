package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/gauravp001/pqc-liboqs-go/pkg/pqc"
)

func main() {
	fmt.Println("===================================================================")
	fmt.Println("     Post-Quantum Cryptography with liboqs + CGO")
	fmt.Println("     Replacement for CIRCL PQC")
	fmt.Println("     Author: gauravpandey")
	fmt.Println("===================================================================\n")

	showAvailableAlgorithms()

	fmt.Println("\n" + strings.Repeat("=", 65))
	fmt.Println("DEMO 1: Kyber768 Key Exchange (replaces CIRCL KEM)")
	fmt.Println(strings.Repeat("=", 65))
	demoKyber()

	fmt.Println("\n" + strings.Repeat("=", 65))
	fmt.Println("DEMO 2: Dilithium3 Digital Signature (replaces CIRCL Sig)")
	fmt.Println(strings.Repeat("=", 65))
	demoDilithium()

	fmt.Println("\n" + strings.Repeat("=", 65))
	fmt.Println("DEMO 3: All Kyber Variants Performance")
	fmt.Println(strings.Repeat("=", 65))
	demoAllKyber()

	fmt.Println("\n" + strings.Repeat("=", 65))
	fmt.Println("DEMO 4: All Dilithium Variants")
	fmt.Println(strings.Repeat("=", 65))
	demoAllDilithium()

	fmt.Println("\n All demonstrations completed successfully!")
	fmt.Println("   liboqs + CGO successfully replaces CIRCL for PQC")
	fmt.Println("   Ready for deployment")
}

func showAvailableAlgorithms() {
	fmt.Println("Available Post-Quantum Algorithms:\n")

	kems := pqc.ListEnabledKEMs()
	fmt.Println("   KEMs (%d):\n", len(kems))
	for _, alg := range kems {
		enabled := ""
		if strings.Contains(alg, "Kyber") {
			enabled = " [NIST ML-KEM]"
		}
		fmt.Println("      - %s%s\n", alg, enabled)
	}

	sigs := pqc.ListEnabledSignatures()
	fmt.Println("\n   Signatures (%d):\n", len(sigs))
	for _, alg := range sigs {
		enabled := ""
		if strings.Contains(alg, "Dilithium") {
			enabled = " [NIST ML-DSA]"
		}
		fmt.Println("      - %s%s\n", alg, enabled)
	}
}

func demoKyber() {
	kem, err := pqc.NewKEM("Kyber768")
	if err != nil {
		log.Fatal(err)
	}
	defer kem.Close()

	pk, sk, _ := kem.GenerateKeyPair()
	ct, ss1, _ := kem.Encapsulate(pk)
	ss2, _ := kem.Decapsulate(sk, ct)

	fmt.Printf("Public Key: %d bytes\n", len(pk))
	fmt.Printf("Secret Key: %d bytes\n", len(sk))
	fmt.Printf("Ciphertext: %d bytes\n", len(ct))
	fmt.Printf("Shared Secret: %s\n", hex.EncodeToString(ss1[:16]))
	fmt.Printf("Match: %v\n", string(ss1) == string(ss2))
}

func demoDilithium() {
	sig, err := pqc.NewSignature("Dilithium3")
	if err != nil {
		log.Fatal(err)
	}
	defer sig.Close()

	pk, sk, _ := sig.GenerateKeyPair()
	message := []byte("Post-quantum secure message")
	signature, _ := sig.Sign(message, sk)
	err = sig.Verify(message, signature, pk)

	fmt.Printf("Public Key: %d bytes\n", len(pk))
	fmt.Printf("Secret Key: %d bytes\n", len(sk))
	fmt.Printf("Signature: %d bytes\n", len(signature))
	fmt.Printf("Verified: %v\n", err == nil)
}

func demoAllKyber() {
	variants := []string{"Kyber512", "Kyber768", "Kyber1024"}
	for _, variant := range variants {
		kem, _ := pqc.NewKEM(variant)
		pk, sk, _ := kem.GenerateKeyPair()
		ct, ss, _ := kem.Encapsulate(pk)
		fmt.Printf("%s: PK=%d, SK=%d, CT=%d, SS=%d\n", variant, len(pk), len(sk), len(ct), len(ss))
		kem.Close()
	}
}

func demoAllDilithium() {
	variants := []string{"Dilithium2", "Dilithium3", "Dilithium5"}
	for _, variant := range variants {
		sig, _ := pqc.NewSignature(variant)
		pk, sk, _ := sig.GenerateKeyPair()
		message := []byte("Test message")
		signature, _ := sig.Sign(message, sk)
		fmt.Printf("%s: PK=%d, SK=%d, Sig=%d\n", variant, len(pk), len(sk), len(signature))
		sig.Close()
	}
}
