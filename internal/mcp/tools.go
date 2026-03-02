package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/pccr10001/webauthn-mcp/internal/token"
	"github.com/pccr10001/webauthn-mcp/internal/webauthn"
)

func (ms *MCPServer) register(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.Params.Arguments

	tokenID := getStringArg(args, "token_id")
	tok, err := ms.storage.Get(tokenID)
	if err != nil {
		return errorResult(err), nil
	}

	// Build request
	req := webauthn.RegisterRequest{
		Challenge: getStringArg(args, "challenge"),
		RP: webauthn.RPInfo{
			ID:   getStringArg(args, "rp_id"),
			Name: getStringArg(args, "rp_name"),
		},
		User: webauthn.User{
			ID:          getStringArg(args, "user_id"),
			Name:        getStringArg(args, "user_name"),
			DisplayName: getStringArg(args, "user_display_name"),
		},
		Attestation: getStringArg(args, "attestation"),
		ResidentKey: getStringArg(args, "resident_key"),
	}

	if req.RP.Name == "" {
		req.RP.Name = req.RP.ID
	}
	if req.User.DisplayName == "" {
		req.User.DisplayName = req.User.Name
	}

	// Build overrides
	var overrides *webauthn.RegisterOverrides
	origin := getStringArg(args, "origin")
	uv := getBoolArg(args, "user_verification")
	up := getBoolArg(args, "user_present")
	counter := getNumberArg(args, "counter")
	invalidSig := getBoolArg(args, "invalid_signature")
	transport := getStringArrayArg(args, "transport")

	if origin != "" || uv != nil || up != nil || counter != nil || invalidSig != nil || len(transport) > 0 {
		overrides = &webauthn.RegisterOverrides{
			UserVerification: uv,
			UserPresent:      up,
			Counter:          counter,
			InvalidSignature: invalidSig,
			Transport:        transport,
		}
		if origin != "" {
			overrides.Origin = &origin
		}
	}

	resp, cred, err := webauthn.Register(tok, req, overrides)
	if err != nil {
		return errorResult(err), nil
	}

	// Save credential
	tok.AddCredential(*cred)
	if err := ms.storage.Save(tok); err != nil {
		return errorResult(err), nil
	}

	// Format response as JSON
	respJSON, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return errorResult(err), nil
	}

	result := fmt.Sprintf("Registration successful!\n\nCredential ID: %s\nRP ID: %s\nUser: %s\n\nResponse:\n%s",
		cred.CredentialID, cred.RPId, cred.UserName, string(respJSON))

	return textResult(result), nil
}

func (ms *MCPServer) authenticate(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.Params.Arguments

	tokenID := getStringArg(args, "token_id")
	tok, err := ms.storage.Get(tokenID)
	if err != nil {
		return errorResult(err), nil
	}

	rpID := getStringArg(args, "rp_id")
	credentialID := getStringArg(args, "credential_id")

	// Find credential
	var cred *token.Credential
	if credentialID != "" {
		cred, err = tok.GetCredential(credentialID)
	} else {
		cred, err = tok.GetCredentialByRPId(rpID)
	}
	if err != nil {
		return errorResult(fmt.Errorf("credential not found: %w", err)), nil
	}

	// Build request
	req := webauthn.AuthenticateRequest{
		Challenge: getStringArg(args, "challenge"),
		RPId:      rpID,
	}

	// Build overrides
	var overrides *webauthn.AuthenticateOverrides
	origin := getStringArg(args, "origin")
	uv := getBoolArg(args, "user_verification")
	up := getBoolArg(args, "user_present")
	counter := getNumberArg(args, "counter")
	invalidSig := getBoolArg(args, "invalid_signature")
	wrongCred := getBoolArg(args, "wrong_credential")

	if origin != "" || uv != nil || up != nil || counter != nil || invalidSig != nil || wrongCred != nil {
		overrides = &webauthn.AuthenticateOverrides{
			UserVerification: uv,
			UserPresent:      up,
			Counter:          counter,
			InvalidSignature: invalidSig,
			WrongCredential:  wrongCred,
		}
		if origin != "" {
			overrides.Origin = &origin
		}
	}

	resp, err := webauthn.Authenticate(cred, req, overrides)
	if err != nil {
		return errorResult(err), nil
	}

	// Update counter (unless overridden)
	if overrides == nil || overrides.Counter == nil {
		cred.IncrementCounter()
		if err := ms.storage.Save(tok); err != nil {
			return errorResult(err), nil
		}
	}

	// Format response as JSON
	respJSON, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return errorResult(err), nil
	}

	result := fmt.Sprintf("Authentication successful!\n\nCredential ID: %s\nCounter: %d\n\nResponse:\n%s",
		cred.CredentialID, cred.Counter, string(respJSON))

	return textResult(result), nil
}
