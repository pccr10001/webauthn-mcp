package webauthn

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"time"

	"github.com/pccr10001/webauthn-mcp/internal/token"
)

type RegisterRequest struct {
	Challenge     string `json:"challenge"`
	RP            RPInfo `json:"rp"`
	User          User   `json:"user"`
	Attestation   string `json:"attestation"`
	ResidentKey   string `json:"residentKey"`
}

type RPInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type User struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type RegisterOverrides struct {
	Origin           *string   `json:"origin,omitempty"`
	RPId             *string   `json:"rp_id,omitempty"`
	UserVerification *bool     `json:"user_verification,omitempty"`
	UserPresent      *bool     `json:"user_present,omitempty"`
	BackupEligible   *bool     `json:"backup_eligible,omitempty"`
	BackupState      *bool     `json:"backup_state,omitempty"`
	Counter          *uint32   `json:"counter,omitempty"`
	AAGUID           *string   `json:"aaguid,omitempty"`
	AttestationType  *string   `json:"attestation_type,omitempty"`
	Transport        []string  `json:"transport,omitempty"`
	InvalidSignature *bool     `json:"invalid_signature,omitempty"`
	Extensions       map[string]interface{} `json:"extensions,omitempty"`
}

type RegisterResponse struct {
	ID                     string   `json:"id"`
	RawID                  string   `json:"rawId"`
	Type                   string   `json:"type"`
	AuthenticatorAttachment string  `json:"authenticatorAttachment,omitempty"`
	ClientExtensionResults map[string]interface{} `json:"clientExtensionResults"`
	Response               AttestationResponse `json:"response"`
}

type AttestationResponse struct {
	ClientDataJSON    string   `json:"clientDataJSON"`
	AttestationObject string   `json:"attestationObject"`
	Transports        []string `json:"transports,omitempty"`
	PublicKey         string   `json:"publicKey,omitempty"`
	PublicKeyAlgorithm int     `json:"publicKeyAlgorithm"`
	AuthenticatorData string   `json:"authenticatorData,omitempty"`
}

type ClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
}

func Register(tok *token.Token, req RegisterRequest, overrides *RegisterOverrides) (*RegisterResponse, *token.Credential, error) {
	// Generate key pair
	keyPair, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	// Generate credential ID
	credentialIDBytes, err := GenerateCredentialID()
	if err != nil {
		return nil, nil, err
	}
	credentialID := base64.RawURLEncoding.EncodeToString(credentialIDBytes)

	// Determine values (with overrides)
	origin := "https://" + req.RP.ID
	rpId := req.RP.ID
	userVerification := true
	userPresent := true
	backupEligible := false
	backupState := false
	var counter uint32 = 0
	var aaguid []byte = make([]byte, 16) // Default: all zeros
	attestationType := AttestationType(req.Attestation)
	if attestationType == "" {
		attestationType = AttestationNone
	}
	transports := []string{"internal"}
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
		if overrides.BackupEligible != nil {
			backupEligible = *overrides.BackupEligible
		}
		if overrides.BackupState != nil {
			backupState = *overrides.BackupState
		}
		if overrides.Counter != nil {
			counter = *overrides.Counter
		}
		if overrides.AAGUID != nil {
			// Decode hex string to bytes
			decoded, err := base64.RawURLEncoding.DecodeString(*overrides.AAGUID)
			if err == nil && len(decoded) == 16 {
				aaguid = decoded
			}
		}
		if overrides.AttestationType != nil {
			attestationType = AttestationType(*overrides.AttestationType)
		}
		if len(overrides.Transport) > 0 {
			transports = overrides.Transport
		}
		if overrides.InvalidSignature != nil {
			invalidSignature = *overrides.InvalidSignature
		}
	}

	// Create client data JSON
	clientData := ClientData{
		Type:      "webauthn.create",
		Challenge: req.Challenge,
		Origin:    origin,
	}
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return nil, nil, err
	}
	clientDataHash := HashClientData(clientDataJSON)

	// Get COSE public key
	publicKeyCOSE, err := keyPair.PublicKeyCOSE()
	if err != nil {
		return nil, nil, err
	}

	// Build authenticator data
	authData := buildAuthenticatorData(rpId, userPresent, userVerification, backupEligible, backupState, counter, aaguid, credentialIDBytes, publicKeyCOSE)

	// Create attestation object
	var attestationObject []byte
	if attestationType == AttestationPacked {
		attestationObject, err = CreatePackedAttestation(authData, clientDataHash, keyPair.PrivateKey, invalidSignature)
	} else {
		attestationObject, err = CreateNoneAttestation(authData)
	}
	if err != nil {
		return nil, nil, err
	}

	// Create credential for storage
	privateKeyB64, err := keyPair.PrivateKeyBase64()
	if err != nil {
		return nil, nil, err
	}
	publicKeyB64, err := keyPair.PublicKeyBase64()
	if err != nil {
		return nil, nil, err
	}

	residentKey := req.ResidentKey == "required" || req.ResidentKey == "preferred"

	cred := &token.Credential{
		CredentialID:    credentialID,
		PrivateKey:      privateKeyB64,
		PublicKey:       publicKeyB64,
		RPId:            req.RP.ID,
		UserHandle:      req.User.ID,
		UserName:        req.User.Name,
		UserDisplayName: req.User.DisplayName,
		Counter:         counter,
		ResidentKey:     residentKey,
		CreatedAt:       time.Now(),
	}

	// Build response
	resp := &RegisterResponse{
		ID:    credentialID,
		RawID: credentialID,
		Type:  "public-key",
		ClientExtensionResults: make(map[string]interface{}),
		Response: AttestationResponse{
			ClientDataJSON:     base64.RawURLEncoding.EncodeToString(clientDataJSON),
			AttestationObject:  base64.RawURLEncoding.EncodeToString(attestationObject),
			Transports:         transports,
			PublicKey:          publicKeyB64,
			PublicKeyAlgorithm: COSEAlgES256,
			AuthenticatorData:  base64.RawURLEncoding.EncodeToString(authData),
		},
	}

	if overrides != nil && overrides.Extensions != nil {
		resp.ClientExtensionResults = overrides.Extensions
	}

	return resp, cred, nil
}

func buildAuthenticatorData(rpId string, userPresent, userVerified, backupEligible, backupState bool, counter uint32, aaguid, credentialID, publicKey []byte) []byte {
	// RP ID hash (32 bytes)
	rpIdHash := sha256.Sum256([]byte(rpId))

	// Flags (1 byte)
	var flags byte = 0
	if userPresent {
		flags |= 0x01 // UP (bit 0)
	}
	if userVerified {
		flags |= 0x04 // UV (bit 2)
	}
	if backupEligible {
		flags |= 0x08 // BE (bit 3)
	}
	if backupState {
		flags |= 0x10 // BS (bit 4)
	}
	flags |= 0x40 // AT (bit 6) - attested credential data

	// Counter (4 bytes, big endian)
	counterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(counterBytes, counter)

	// Credential ID length (2 bytes, big endian)
	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credentialID)))

	// Build authenticator data
	authData := make([]byte, 0, 32+1+4+16+2+len(credentialID)+len(publicKey))
	authData = append(authData, rpIdHash[:]...)
	authData = append(authData, flags)
	authData = append(authData, counterBytes...)
	authData = append(authData, aaguid...)
	authData = append(authData, credIDLen...)
	authData = append(authData, credentialID...)
	authData = append(authData, publicKey...)

	return authData
}
