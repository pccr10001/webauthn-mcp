package token

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrCredentialNotFound = errors.New("credential not found")
	ErrTokenNotFound      = errors.New("token not found")
)

type Token struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	CreatedAt   time.Time    `json:"created_at"`
	Credentials []Credential `json:"credentials"`
}

func NewToken(name string) *Token {
	if name == "" {
		name = "Token-" + uuid.New().String()[:8]
	}
	return &Token{
		ID:          uuid.New().String(),
		Name:        name,
		CreatedAt:   time.Now(),
		Credentials: []Credential{},
	}
}

func (t *Token) AddCredential(cred Credential) {
	t.Credentials = append(t.Credentials, cred)
}

func (t *Token) GetCredential(credentialID string) (*Credential, error) {
	for i := range t.Credentials {
		if t.Credentials[i].CredentialID == credentialID {
			return &t.Credentials[i], nil
		}
	}
	return nil, ErrCredentialNotFound
}

func (t *Token) GetCredentialByRPId(rpId string) (*Credential, error) {
	for i := range t.Credentials {
		if t.Credentials[i].RPId == rpId {
			return &t.Credentials[i], nil
		}
	}
	return nil, ErrCredentialNotFound
}

func (t *Token) GetCredentialByUserHandle(userHandle string) (*Credential, error) {
	for i := range t.Credentials {
		if t.Credentials[i].UserHandle == userHandle {
			return &t.Credentials[i], nil
		}
	}
	return nil, ErrCredentialNotFound
}

func (t *Token) DeleteCredential(credentialID string) error {
	for i := range t.Credentials {
		if t.Credentials[i].CredentialID == credentialID {
			t.Credentials = append(t.Credentials[:i], t.Credentials[i+1:]...)
			return nil
		}
	}
	return ErrCredentialNotFound
}

func (t *Token) ListResidentCredentials(rpId string) []Credential {
	var creds []Credential
	for _, c := range t.Credentials {
		if c.ResidentKey && c.RPId == rpId {
			creds = append(creds, c)
		}
	}
	return creds
}
