package pqc

/*
#cgo CFLAGS: -I/opt/homebrew/include -I/opt/homebrew/opt/openssl@3/include
#cgo LDFLAGS: -L/opt/homebrew/lib -L/opt/homebrew/opt/openssl@3/lib -loqs -lcrypto -lssl
#include <oqs/oqs.h>
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

type KEM struct {
	algorithm string
	kem       *C.OQS_KEM
}

func NewKEM(algorithm string) (*KEM, error) {
	cAlg := C.CString(algorithm)
	defer C.free(unsafe.Pointer(cAlg))
	kem := C.OQS_KEM_new(cAlg)
	if kem == nil {
		return nil, fmt.Errorf("failed to init KEM: %s", algorithm)
	}
	return &KEM{algorithm: algorithm, kem: kem}, nil
}

func (k *KEM) GenerateKeyPair() ([]byte, []byte, error) {
	if k.kem == nil {
		return nil, nil, errors.New("KEM closed")
	}
	pk := make([]byte, k.kem.length_public_key)
	sk := make([]byte, k.kem.length_secret_key)
	rc := C.OQS_KEM_keypair(k.kem, (*C.uint8_t)(unsafe.Pointer(&pk[0])), (*C.uint8_t)(unsafe.Pointer(&sk[0])))
	if rc != C.OQS_SUCCESS {
		return nil, nil, errors.New("keygen failed")
	}
	return pk, sk, nil
}

func (k *KEM) Encapsulate(pk []byte) ([]byte, []byte, error) {
	if k.kem == nil {
		return nil, nil, errors.New("KEM closed")
	}
	ct := make([]byte, k.kem.length_ciphertext)
	ss := make([]byte, k.kem.length_shared_secret)
	rc := C.OQS_KEM_encaps(k.kem, (*C.uint8_t)(unsafe.Pointer(&ct[0])), (*C.uint8_t)(unsafe.Pointer(&ss[0])), (*C.uint8_t)(unsafe.Pointer(&pk[0])))
	if rc != C.OQS_SUCCESS {
		return nil, nil, errors.New("encaps failed")
	}
	return ct, ss, nil
}

func (k *KEM) Decapsulate(sk, ct []byte) ([]byte, error) {
	if k.kem == nil {
		return nil, errors.New("KEM closed")
	}
	ss := make([]byte, k.kem.length_shared_secret)
	rc := C.OQS_KEM_decaps(k.kem, (*C.uint8_t)(unsafe.Pointer(&ss[0])), (*C.uint8_t)(unsafe.Pointer(&ct[0])), (*C.uint8_t)(unsafe.Pointer(&sk[0])))
	if rc != C.OQS_SUCCESS {
		return nil, errors.New("decaps failed")
	}
	return ss, nil
}

func (k *KEM) Close() {
	if k.kem != nil {
		C.OQS_KEM_free(k.kem)
		k.kem = nil
	}
}

func ListEnabledKEMs() []string {
	var kems []string
	for i := 0; ; i++ {
		alg := C.OQS_KEM_alg_identifier(C.size_t(i))
		if alg == nil {
			break
		}
		kems = append(kems, C.GoString(alg))
	}
	return kems
}
