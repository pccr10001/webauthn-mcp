package mcp

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/pccr10001/webauthn-mcp/internal/token"
)

type MCPServer struct {
	server  *server.MCPServer
	storage *token.Storage
}

func NewMCPServer(storage *token.Storage) *MCPServer {
	s := server.NewMCPServer(
		"webauthn-mcp",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	ms := &MCPServer{
		server:  s,
		storage: storage,
	}

	ms.registerTools()

	return ms
}

func (ms *MCPServer) Serve() error {
	return server.ServeStdio(ms.server)
}

func (ms *MCPServer) registerTools() {
	// create_token
	ms.server.AddTool(mcp.NewTool("create_token",
		mcp.WithDescription("Create a new WebAuthn soft token"),
		mcp.WithString("name", mcp.Description("Optional name for the token")),
	), ms.createToken)

	// delete_token
	ms.server.AddTool(mcp.NewTool("delete_token",
		mcp.WithDescription("Delete a WebAuthn soft token"),
		mcp.WithString("token_id", mcp.Required(), mcp.Description("Token ID to delete")),
	), ms.deleteToken)

	// list_tokens
	ms.server.AddTool(mcp.NewTool("list_tokens",
		mcp.WithDescription("List all WebAuthn soft tokens"),
	), ms.listTokens)

	// get_token_info
	ms.server.AddTool(mcp.NewTool("get_token_info",
		mcp.WithDescription("Get detailed information about a token"),
		mcp.WithString("token_id", mcp.Required(), mcp.Description("Token ID")),
	), ms.getTokenInfo)

	// list_credentials
	ms.server.AddTool(mcp.NewTool("list_credentials",
		mcp.WithDescription("List all credentials in a token"),
		mcp.WithString("token_id", mcp.Required(), mcp.Description("Token ID")),
	), ms.listCredentials)

	// delete_credential
	ms.server.AddTool(mcp.NewTool("delete_credential",
		mcp.WithDescription("Delete a credential from a token"),
		mcp.WithString("token_id", mcp.Required(), mcp.Description("Token ID")),
		mcp.WithString("credential_id", mcp.Required(), mcp.Description("Credential ID to delete")),
	), ms.deleteCredential)

	// register
	ms.server.AddTool(mcp.NewTool("register",
		mcp.WithDescription("Generate a WebAuthn registration response"),
		mcp.WithString("token_id", mcp.Required(), mcp.Description("Token ID to use")),
		mcp.WithString("challenge", mcp.Required(), mcp.Description("Base64URL encoded challenge")),
		mcp.WithString("rp_id", mcp.Required(), mcp.Description("Relying Party ID (e.g., example.com)")),
		mcp.WithString("rp_name", mcp.Description("Relying Party name")),
		mcp.WithString("user_id", mcp.Required(), mcp.Description("Base64URL encoded user ID")),
		mcp.WithString("user_name", mcp.Required(), mcp.Description("Username")),
		mcp.WithString("user_display_name", mcp.Description("User display name")),
		mcp.WithString("resident_key", mcp.Description("Resident key requirement: required, preferred, discouraged")),
		mcp.WithString("attestation", mcp.Description("Attestation type: none, packed")),
		mcp.WithString("origin", mcp.Description("Override origin (for testing)")),
		mcp.WithBoolean("user_verification", mcp.Description("Override UV flag")),
		mcp.WithBoolean("user_present", mcp.Description("Override UP flag")),
		mcp.WithNumber("counter", mcp.Description("Override counter value")),
		mcp.WithBoolean("invalid_signature", mcp.Description("Generate invalid signature")),
		mcp.WithArray("transport", mcp.Description("Transport types: usb, nfc, ble, internal")),
	), ms.register)

	// authenticate
	ms.server.AddTool(mcp.NewTool("authenticate",
		mcp.WithDescription("Generate a WebAuthn authentication response"),
		mcp.WithString("token_id", mcp.Required(), mcp.Description("Token ID to use")),
		mcp.WithString("challenge", mcp.Required(), mcp.Description("Base64URL encoded challenge")),
		mcp.WithString("rp_id", mcp.Required(), mcp.Description("Relying Party ID")),
		mcp.WithString("credential_id", mcp.Description("Specific credential ID to use (optional for resident key)")),
		mcp.WithString("origin", mcp.Description("Override origin (for testing)")),
		mcp.WithBoolean("user_verification", mcp.Description("Override UV flag")),
		mcp.WithBoolean("user_present", mcp.Description("Override UP flag")),
		mcp.WithNumber("counter", mcp.Description("Override counter value")),
		mcp.WithBoolean("invalid_signature", mcp.Description("Generate invalid signature")),
		mcp.WithBoolean("wrong_credential", mcp.Description("Return wrong credential ID")),
	), ms.authenticate)
}

func ptr[T any](v T) *T {
	return &v
}

func toArgsMap(args any) map[string]interface{} {
	if m, ok := args.(map[string]interface{}); ok {
		return m
	}
	return make(map[string]interface{})
}

func getStringArg(args any, key string) string {
	m := toArgsMap(args)
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getBoolArg(args any, key string) *bool {
	m := toArgsMap(args)
	if v, ok := m[key].(bool); ok {
		return &v
	}
	return nil
}

func getNumberArg(args any, key string) *uint32 {
	m := toArgsMap(args)
	if v, ok := m[key].(float64); ok {
		u := uint32(v)
		return &u
	}
	return nil
}

func getStringArrayArg(args any, key string) []string {
	m := toArgsMap(args)
	if v, ok := m[key].([]interface{}); ok {
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func textResult(text string) *mcp.CallToolResult {
	return mcp.NewToolResultText(text)
}

func errorResult(err error) *mcp.CallToolResult {
	return mcp.NewToolResultError(err.Error())
}

func (ms *MCPServer) createToken(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := getStringArg(request.Params.Arguments, "name")
	tok := token.NewToken(name)
	if err := ms.storage.Save(tok); err != nil {
		return errorResult(err), nil
	}
	return textResult("Created token: " + tok.ID + " (" + tok.Name + ")"), nil
}

func (ms *MCPServer) deleteToken(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tokenID := getStringArg(request.Params.Arguments, "token_id")
	if err := ms.storage.Delete(tokenID); err != nil {
		return errorResult(err), nil
	}
	return textResult("Deleted token: " + tokenID), nil
}

func (ms *MCPServer) listTokens(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tokens := ms.storage.List()
	if len(tokens) == 0 {
		return textResult("No tokens found"), nil
	}
	result := "Tokens:\n"
	for _, tok := range tokens {
		result += "- " + tok.ID + " (" + tok.Name + ") - " + string(rune(len(tok.Credentials))) + " credentials\n"
	}
	return textResult(result), nil
}

func (ms *MCPServer) getTokenInfo(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tokenID := getStringArg(request.Params.Arguments, "token_id")
	tok, err := ms.storage.Get(tokenID)
	if err != nil {
		return errorResult(err), nil
	}
	result := "Token: " + tok.ID + "\n"
	result += "Name: " + tok.Name + "\n"
	result += "Created: " + tok.CreatedAt.Format("2006-01-02T15:04:05Z07:00") + "\n"
	result += "Credentials: " + string(rune('0'+len(tok.Credentials))) + "\n"
	return textResult(result), nil
}

func (ms *MCPServer) listCredentials(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tokenID := getStringArg(request.Params.Arguments, "token_id")
	tok, err := ms.storage.Get(tokenID)
	if err != nil {
		return errorResult(err), nil
	}
	if len(tok.Credentials) == 0 {
		return textResult("No credentials found"), nil
	}
	result := "Credentials:\n"
	for _, cred := range tok.Credentials {
		result += "- " + cred.CredentialID[:16] + "... (RP: " + cred.RPId + ", User: " + cred.UserName + ")\n"
	}
	return textResult(result), nil
}

func (ms *MCPServer) deleteCredential(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tokenID := getStringArg(request.Params.Arguments, "token_id")
	credentialID := getStringArg(request.Params.Arguments, "credential_id")

	tok, err := ms.storage.Get(tokenID)
	if err != nil {
		return errorResult(err), nil
	}
	if err := tok.DeleteCredential(credentialID); err != nil {
		return errorResult(err), nil
	}
	if err := ms.storage.Save(tok); err != nil {
		return errorResult(err), nil
	}
	return textResult("Deleted credential: " + credentialID), nil
}
