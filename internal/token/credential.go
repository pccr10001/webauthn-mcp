package token

import (
	"time"
)

type Credential struct {
	CredentialID    string    `json:"credential_id"`
	PrivateKey      string    `json:"private_key"`
	PublicKey       string    `json:"public_key"`
	RPId            string    `json:"rp_id"`
	UserHandle      string    `json:"user_handle"`
	UserName        string    `json:"user_name"`
	UserDisplayName string    `json:"user_display_name"`
	Counter         uint32    `json:"counter"`
	ResidentKey     bool      `json:"resident_key"`
	CreatedAt       time.Time `json:"created_at"`
}

func (c *Credential) IncrementCounter() {
	c.Counter++
}
