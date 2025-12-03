package pqc

import (
	"fmt"
	"testing"
)

func TestListAlgorithms(t *testing.T) {
	fmt.Println("\n=== Available KEM Algorithms ===")
	kems := ListEnabledKEMs()
	for i, k := range kems {
		fmt.Printf("%2d. %s\n", i+1, k)
	}
	
	fmt.Println("\n=== Available Signature Algorithms ===")
	sigs := ListEnabledSignatures()
	for i, s := range sigs {
		fmt.Printf("%2d. %s\n", i+1, s)
	}
}
