package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"math/big"
)

type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

func (kp *KeyPair) PrivateKeyBase64() (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(kp.PrivateKey)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(der), nil
}

func (kp *KeyPair) PublicKeyCOSE() ([]byte, error) {
	return EncodeCOSEPublicKey(kp.PublicKey)
}

func (kp *KeyPair) PublicKeyBase64() (string, error) {
	cose, err := kp.PublicKeyCOSE()
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(cose), nil
}

func LoadPrivateKey(base64Key string) (*ecdsa.PrivateKey, error) {
	der, err := base64.RawURLEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	return key.(*ecdsa.PrivateKey), nil
}

func Sign(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, err
	}
	return encodeSignature(r, s), nil
}

func SignWithInvalidSignature(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	sig, err := Sign(privateKey, data)
	if err != nil {
		return nil, err
	}
	// Corrupt the signature by flipping a bit
	if len(sig) > 0 {
		sig[0] ^= 0x01
	}
	return sig, nil
}

func encodeSignature(r, s *big.Int) []byte {
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Pad to 32 bytes each
	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	// DER encode
	sig := make([]byte, 0, 72)
	sig = append(sig, 0x30) // SEQUENCE

	rEncoded := derEncodeInteger(rPadded)
	sEncoded := derEncodeInteger(sPadded)

	sig = append(sig, byte(len(rEncoded)+len(sEncoded)))
	sig = append(sig, rEncoded...)
	sig = append(sig, sEncoded...)

	return sig
}

func derEncodeInteger(b []byte) []byte {
	// Remove leading zeros
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}

	// Add leading zero if high bit is set
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}

	result := make([]byte, 0, len(b)+2)
	result = append(result, 0x02) // INTEGER
	result = append(result, byte(len(b)))
	result = append(result, b...)
	return result
}

func GenerateCredentialID() ([]byte, error) {
	id := make([]byte, 32)
	_, err := rand.Read(id)
	return id, err
}
