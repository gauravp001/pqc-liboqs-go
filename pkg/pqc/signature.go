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

type Signature struct {
	algorithm string
	sig       *C.OQS_SIG
}

func NewSignature(algorithm string) (*Signature, error) {
	cAlg := C.CString(algorithm)
	defer C.free(unsafe.Pointer(cAlg))
	sig := C.OQS_SIG_new(cAlg)
	if sig == nil {
		return nil, fmt.Errorf("failed to init signature: %s", algorithm)
	}
	return &Signature{algorithm: algorithm, sig: sig}, nil
}

func (s *Signature) GenerateKeyPair() ([]byte, []byte, error) {
	if s.sig == nil {
		return nil, nil, errors.New("signature closed")
	}
	pk := make([]byte, s.sig.length_public_key)
	sk := make([]byte, s.sig.length_secret_key)
	rc := C.OQS_SIG_keypair(s.sig, (*C.uint8_t)(unsafe.Pointer(&pk[0])), (*C.uint8_t)(unsafe.Pointer(&sk[0])))
	if rc != C.OQS_SUCCESS {
		return nil, nil, errors.New("keygen failed")
	}
	return pk, sk, nil
}

func (s *Signature) Sign(msg, sk []byte) ([]byte, error) {
	if s.sig == nil {
		return nil, errors.New("signature closed")
	}
	signature := make([]byte, s.sig.length_signature)
	var sigLen C.size_t
	rc := C.OQS_SIG_sign(s.sig, (*C.uint8_t)(unsafe.Pointer(&signature[0])), &sigLen, (*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)), (*C.uint8_t)(unsafe.Pointer(&sk[0])))
	if rc != C.OQS_SUCCESS {
		return nil, errors.New("signing failed")
	}
	return signature[:sigLen], nil
}

func (s *Signature) Verify(msg, sig, pk []byte) error {
	if s.sig == nil {
		return errors.New("signature closed")
	}
	rc := C.OQS_SIG_verify(s.sig, (*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)), (*C.uint8_t)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)), (*C.uint8_t)(unsafe.Pointer(&pk[0])))
	if rc != C.OQS_SUCCESS {
		return errors.New("verification failed")
	}
	return nil
}

func (s *Signature) Close() {
	if s.sig != nil {
		C.OQS_SIG_free(s.sig)
		s.sig = nil
	}
}

func ListEnabledSignatures() []string {
	var sigs []string
	for i := 0; ; i++ {
		alg := C.OQS_SIG_alg_identifier(C.size_t(i))
		if alg == nil {
			break
		}
		sigs = append(sigs, C.GoString(alg))
	}
	return sigs
}
