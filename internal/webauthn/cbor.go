package webauthn

import (
	"crypto/ecdsa"

	"github.com/fxamacker/cbor/v2"
)

// COSE Key Types
const (
	COSEKeyTypeEC2 = 2
	COSEAlgES256   = -7
	COSEP256Curve  = 1
)

// COSE Key Parameters
const (
	COSEKeyType   = 1
	COSEKeyAlg    = 3
	COSEKeyCurve  = -1
	COSEKeyXCoord = -2
	COSEKeyYCoord = -3
)

type COSEKey struct {
	_           struct{} `cbor:",toarray"`
	KeyType     int      `cbor:"1,keyasint"`
	Algorithm   int      `cbor:"3,keyasint"`
	Curve       int      `cbor:"-1,keyasint"`
	XCoord      []byte   `cbor:"-2,keyasint"`
	YCoord      []byte   `cbor:"-3,keyasint"`
}

func EncodeCOSEPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	x := pub.X.Bytes()
	y := pub.Y.Bytes()

	// Pad to 32 bytes
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(x):], x)
	copy(yPadded[32-len(y):], y)

	// CBOR map encoding
	coseKey := map[int]interface{}{
		COSEKeyType:   COSEKeyTypeEC2,
		COSEKeyAlg:    COSEAlgES256,
		COSEKeyCurve:  COSEP256Curve,
		COSEKeyXCoord: xPadded,
		COSEKeyYCoord: yPadded,
	}

	return cbor.Marshal(coseKey)
}

func EncodeCBOR(v interface{}) ([]byte, error) {
	return cbor.Marshal(v)
}

func DecodeCBOR(data []byte, v interface{}) error {
	return cbor.Unmarshal(data, v)
}
