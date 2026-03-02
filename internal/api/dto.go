package api

import (
	"github.com/pccr10001/webauthn-mcp/internal/webauthn"
)

// Token DTOs
type CreateTokenRequest struct {
	Name string `json:"name,omitempty"`
}

type TokenResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	CredentialCount int `json:"credential_count"`
}

type CredentialResponse struct {
	CredentialID    string `json:"credential_id"`
	RPId            string `json:"rp_id"`
	UserHandle      string `json:"user_handle"`
	UserName        string `json:"user_name"`
	UserDisplayName string `json:"user_display_name"`
	Counter         uint32 `json:"counter"`
	ResidentKey     bool   `json:"resident_key"`
	CreatedAt       string `json:"created_at"`
}

// Register DTOs
type RegisterRequestDTO struct {
	Request   webauthn.RegisterRequest    `json:"request"`
	Overrides *webauthn.RegisterOverrides `json:"overrides,omitempty"`
}

type RegisterResponseDTO struct {
	Response   *webauthn.RegisterResponse `json:"response"`
	Credential *CredentialResponse        `json:"credential"`
}

// Authenticate DTOs
type AuthenticateRequestDTO struct {
	Request      webauthn.AuthenticateRequest    `json:"request"`
	CredentialID string                          `json:"credential_id,omitempty"`
	Overrides    *webauthn.AuthenticateOverrides `json:"overrides,omitempty"`
}

type AuthenticateResponseDTO struct {
	Response *webauthn.AuthenticateResponse `json:"response"`
	Counter  uint32                          `json:"counter"`
}

// Error DTO
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}
