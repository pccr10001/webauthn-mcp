package webauthn

import (
	"crypto/ecdsa"
	"crypto/sha256"

	"github.com/fxamacker/cbor/v2"
)

type AttestationType string

const (
	AttestationNone   AttestationType = "none"
	AttestationPacked AttestationType = "packed"
)

type AttestationObject struct {
	AuthData []byte                 `cbor:"authData"`
	Fmt      string                 `cbor:"fmt"`
	AttStmt  map[string]interface{} `cbor:"attStmt"`
}

func CreateNoneAttestation(authData []byte) ([]byte, error) {
	obj := AttestationObject{
		AuthData: authData,
		Fmt:      "none",
		AttStmt:  map[string]interface{}{},
	}
	return cbor.Marshal(obj)
}

func CreatePackedAttestation(authData []byte, clientDataHash []byte, privateKey *ecdsa.PrivateKey, invalidSig bool) ([]byte, error) {
	// Create signature over authData || clientDataHash
	signedData := append(authData, clientDataHash...)

	var sig []byte
	var err error
	if invalidSig {
		sig, err = SignWithInvalidSignature(privateKey, signedData)
	} else {
		sig, err = Sign(privateKey, signedData)
	}
	if err != nil {
		return nil, err
	}

	obj := AttestationObject{
		AuthData: authData,
		Fmt:      "packed",
		AttStmt: map[string]interface{}{
			"alg": COSEAlgES256,
			"sig": sig,
		},
	}
	return cbor.Marshal(obj)
}

func HashClientData(clientDataJSON []byte) []byte {
	hash := sha256.Sum256(clientDataJSON)
	return hash[:]
}
