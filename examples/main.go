package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/gauravp001/pqc-liboqs-go/pkg/pqc"
)

func main() {
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║     Post-Quantum Cryptography with liboqs + CGO          ║")
	fmt.Println("║     Replacement for CIRCL PQC (QC)                        ║")
	fmt.Println("║     Author: gauravpandey                                  ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝\n")

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
	fmt.Println("   Ready for QC IoT deployment")
}

func showAvailableAlgorithms() {
	fmt.Println("📋 Available Post-Quantum Algorithms:\n")

	kems := pqc.ListEnabledKEMs()
	fmt.Printf("   KEMs (%d):\n", len(kems))
	for _, alg := range kems {
		enabled := ""
		if strings.Contains(alg, "Kyber") {
			enabled = " ✓ [NIST ML-KEM]"
		}
		fmt.Printf("     - %s%s\n", alg, enabled)
	}

	sigs := pqc.ListEnabledSignatures()
	fmt.Printf("\n   Signatures (%d):\n", len(sigs))
	for _, alg := range sigs {
		enabled := ""
		if strings.Contains(alg, "Dilithium") {
			enabled = " ✓ [NIST ML-DSA]"
		}
		fmt.Printf("     - %s%s\n", alg, enabled)
	}
}

func demoKyber() {
	kem, err := pqc.NewKEM("Kyber768")
	if err != nil {
		log.Fatal(err)
	}
	defer kem.Close()

	details := kem.Details()
	fmt.Printf("\n %s Algorithm Details:\n", details.Name)
	fmt.Printf("   Public Key:  %4d bytes\n", details.PublicKeyBytes)
	fmt.Printf("   Secret Key:  %4d bytes\n", details.SecretKeyBytes)
	fmt.Printf("   Ciphertext:  %4d bytes\n", details.CiphertextBytes)
	fmt.Printf("   Shared Key:  %4d bytes\n\n", details.SharedSecretBytes)

	fmt.Println(" Scenario: IoT Sensor ↔ Gateway Secure Channel\n")

	fmt.Println("   [Gateway] Generating Kyber768 key pair...")
	publicKey, secretKey, err := kem.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   ✓ Public key: %s... (%d bytes)\n",
		hex.EncodeToString(publicKey[:32]), len(publicKey))

	fmt.Println("\n   [IoT Sensor] Creating shared secret via encapsulation...")
	ciphertext, sensorSecret, err := kem.Encapsulate(publicKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   ✓ Ciphertext: %s... (%d bytes)\n",
		hex.EncodeToString(ciphertext[:32]), len(ciphertext))
	fmt.Printf("   ✓ Sensor's shared secret: %s...\n",
		hex.EncodeToString(sensorSecret[:16]))

	fmt.Println("\n   [Gateway] Recovering shared secret via decapsulation...")
	gatewaySecret, err := kem.Decapsulate(secretKey, ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   ✓ Gateway's shared secret: %s...\n",
		hex.EncodeToString(gatewaySecret[:16]))

	if hex.EncodeToString(sensorSecret) == hex.EncodeToString(gatewaySecret) {
		fmt.Println("\n    SUCCESS! Shared secrets match perfectly")
		fmt.Println("   ➜ Quantum-safe channel established")
		fmt.Println("   ➜ Can now use for AES-256-GCM symmetric encryption")
	}
}

func demoDilithium() {
	sig, err := pqc.NewSignature("Dilithium3")
	if err != nil {
		log.Fatal(err)
	}
	defer sig.Close()

	details := sig.Details()
	fmt.Printf("\n  %s Algorithm Details:\n", details.Name)
	fmt.Printf("   Public Key:  %4d bytes\n", details.PublicKeyBytes)
	fmt.Printf("   Secret Key:  %4d bytes\n", details.SecretKeyBytes)
	fmt.Printf("   Signature:   %4d bytes (variable)\n\n", details.SignatureBytes)

	fmt.Println(" Scenario: QC Firmware Update Authentication\n")

	fmt.Println("   [QC Server] Generating Dilithium3 signing keys...")
	publicKey, secretKey, err := sig.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   ✓ Public key: %s... (%d bytes)\n",
		hex.EncodeToString(publicKey[:32]), len(publicKey))

	firmware := []byte("FIRMWARE_v2.1.0|SHA256:abc123|TIMESTAMP:2025-12-02")
	fmt.Printf("\n   [QC Server] Signing firmware update:\n")
	fmt.Printf("    %s\n", string(firmware))

	signature, err := sig.Sign(firmware, secretKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n   ✓ Digital signature: %s... (%d bytes)\n",
		hex.EncodeToString(signature[:32]), len(signature))

	fmt.Println("\n   [IoT Device] Verifying firmware signature...")
	err = sig.Verify(firmware, signature, publicKey)
	if err != nil {
		log.Fatal(" Verification failed:", err)
	}
	fmt.Println("   ✓ Signature verified successfully!")
	fmt.Println("   ➜ Firmware authenticated by QC")

	// Test tampered firmware
	fmt.Println("\n   [Security Test] Testing tampered firmware...")
	tamperedFirmware := []byte("FIRMWARE_v2.1.0|SHA256:HACKED|TIMESTAMP:2025-12-02")
	err = sig.Verify(tamperedFirmware, signature, publicKey)
	if err != nil {
		fmt.Println("   ✓ Tampered firmware detected and rejected!")
		fmt.Println("   ➜ Security mechanism working correctly")
	}
}

func demoAllKyber() {
	variants := []string{"Kyber512", "Kyber768", "Kyber1024"}

	fmt.Println()
	fmt.Println("Testing all Kyber security levels:\n")
	fmt.Println("Algorithm  │  PK   │  SK   │  CT   │  SS  │ Status")
	fmt.Println("───────────┼───────┼───────┼───────┼──────┼────────")

	for _, variant := range variants {
		kem, err := pqc.NewKEM(variant)
		if err != nil {
			fmt.Printf("%-11s│   -   │   -   │   -   │  -   │  Error\n", variant)
			continue
		}

		details := kem.Details()
		pub, sec, _ := kem.GenerateKeyPair()
		ct, ss1, _ := kem.Encapsulate(pub)
		ss2, _ := kem.Decapsulate(sec, ct)

		match := hex.EncodeToString(ss1) == hex.EncodeToString(ss2)

		status := "✓ Pass"
		if !match {
			status = " Fail"
		}

		fmt.Printf("%-11s│ %4db │ %4db │ %4db │ %2db │ %s\n",
			variant,
			details.PublicKeyBytes,
			details.SecretKeyBytes,
			details.CiphertextBytes,
			details.SharedSecretBytes,
			status)

		kem.Close()
	}
}

func demoAllDilithium() {
	variants := []string{"Dilithium2", "Dilithium3", "Dilithium5"}

	fmt.Println()
	fmt.Println("Testing all Dilithium security levels:\n")
	fmt.Println("Algorithm   │  PK   │  SK   │  Sig  │ Status")
	fmt.Println("────────────┼───────┼───────┼───────┼────────")

	for _, variant := range variants {
		sig, err := pqc.NewSignature(variant)
		if err != nil {
			fmt.Printf("%-12s│   -   │   -   │   -   │  Error\n", variant)
			continue
		}

		details := sig.Details()
		pub, sec, _ := sig.GenerateKeyPair()
		message := []byte("Test message for " + variant)
		signature, _ := sig.Sign(message, sec)
		err = sig.Verify(message, signature, pub)

		status := "✓ Pass"
		if err != nil {
			status = " Fail"
		}

		fmt.Printf("%-12s│ %4db │ %4db │ %4db │ %s\n",
			variant,
			details.PublicKeyBytes,
			details.SecretKeyBytes,
			len(signature),
			status)

		sig.Close()
	}
}
