package webauthn

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"

	"github.com/pccr10001/webauthn-mcp/internal/token"
)

type AuthenticateRequest struct {
	Challenge        string   `json:"challenge"`
	RPId             string   `json:"rpId"`
	AllowCredentials []AllowCredential `json:"allowCredentials,omitempty"`
	UserVerification string   `json:"userVerification,omitempty"`
}

type AllowCredential struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type AuthenticateOverrides struct {
	Origin           *string `json:"origin,omitempty"`
	RPId             *string `json:"rp_id,omitempty"`
	UserVerification *bool   `json:"user_verification,omitempty"`
	UserPresent      *bool   `json:"user_present,omitempty"`
	Counter          *uint32 `json:"counter,omitempty"`
	InvalidSignature *bool   `json:"invalid_signature,omitempty"`
	WrongCredential  *bool   `json:"wrong_credential,omitempty"`
	Extensions       map[string]interface{} `json:"extensions,omitempty"`
}

type AuthenticateResponse struct {
	ID                     string `json:"id"`
	RawID                  string `json:"rawId"`
	Type                   string `json:"type"`
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	ClientExtensionResults map[string]interface{} `json:"clientExtensionResults"`
	Response               AssertionResponse `json:"response"`
}

type AssertionResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

func Authenticate(cred *token.Credential, req AuthenticateRequest, overrides *AuthenticateOverrides) (*AuthenticateResponse, error) {
	// Load private key
	privateKey, err := LoadPrivateKey(cred.PrivateKey)
	if err != nil {
		return nil, err
	}

	// Determine values (with overrides)
	origin := "https://" + req.RPId
	rpId := req.RPId
	userVerification := true
	userPresent := true
	counter := cred.Counter + 1
	invalidSignature := false

	if overrides != nil {
		if overrides.Origin != nil {
			origin = *overrides.Origin
		}
		if overrides.RPId != nil {
			rpId = *overrides.RPId
		}
		if overrides.UserVerification != nil {
			userVerification = *overrides.UserVerification
		}
		if overrides.UserPresent != nil {
			userPresent = *overrides.UserPresent
		}
		if overrides.Counter != nil {
			counter = *overrides.Counter
		}
		if overrides.InvalidSignature != nil {
			invalidSignature = *overrides.InvalidSignature
		}
	}

	// Create client data JSON
	clientData := ClientData{
		Type:      "webauthn.get",
		Challenge: req.Challenge,
		Origin:    origin,
	}
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return nil, err
	}
	clientDataHash := HashClientData(clientDataJSON)

	// Build authenticator data (without attested credential data)
	authData := buildAuthDataForAssertion(rpId, userPresent, userVerification, counter)

	// Sign authData || clientDataHash
	signedData := append(authData, clientDataHash...)
	var signature []byte
	if invalidSignature {
		signature, err = SignWithInvalidSignature(privateKey, signedData)
	} else {
		signature, err = Sign(privateKey, signedData)
	}
	if err != nil {
		return nil, err
	}

	// Build response
	credentialID := cred.CredentialID
	if overrides != nil && overrides.WrongCredential != nil && *overrides.WrongCredential {
		// Generate a random credential ID
		wrongID, err := GenerateCredentialID()
		if err != nil {
			return nil, err
		}
		credentialID = base64.RawURLEncoding.EncodeToString(wrongID)
	}

	resp := &AuthenticateResponse{
		ID:    credentialID,
		RawID: credentialID,
		Type:  "public-key",
		ClientExtensionResults: make(map[string]interface{}),
		Response: AssertionResponse{
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData),
			Signature:         base64.RawURLEncoding.EncodeToString(signature),
			UserHandle:        cred.UserHandle,
		},
	}

	if overrides != nil && overrides.Extensions != nil {
		resp.ClientExtensionResults = overrides.Extensions
	}

	return resp, nil
}

func buildAuthDataForAssertion(rpId string, userPresent, userVerified bool, counter uint32) []byte {
	// RP ID hash (32 bytes)
	rpIdHash := sha256.Sum256([]byte(rpId))

	// Flags (1 byte)
	var flags byte = 0
	if userPresent {
		flags |= 0x01 // UP
	}
	if userVerified {
		flags |= 0x04 // UV
	}

	// Counter (4 bytes, big endian)
	counterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(counterBytes, counter)

	// Build authenticator data (37 bytes for assertion)
	authData := make([]byte, 0, 37)
	authData = append(authData, rpIdHash[:]...)
	authData = append(authData, flags)
	authData = append(authData, counterBytes...)

	return authData
}
