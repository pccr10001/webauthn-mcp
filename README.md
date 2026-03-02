# WebAuthn MCP

A WebAuthn soft token simulator for penetration testing and automated testing. This tool allows you to simulate WebAuthn authenticators (security keys, passkeys) for testing purposes without requiring physical hardware.

## Features

- 🔐 Generate WebAuthn registration and authentication responses
- 🎯 Simulate various authenticator behaviors and edge cases
- 🔧 Customize authenticator flags (UV, UP, BE, BS)
- 🆔 Set custom AAGUID to mimic specific authenticators
- 🌐 HTTP API for easy integration
- 🤖 MCP (Model Context Protocol) server support
- 💾 Persistent token storage

## Quick Start

### Build

```bash
go build -o webauthn-mcp.exe .
```

### Run as HTTP Server

```bash
./webauthn-mcp.exe
```

The server will start on port 8080 (configurable via `config.yaml`).

### Run as MCP Server

```bash
./webauthn-mcp.exe mcp
```

## Configuration

Create or edit `config.yaml`:

```yaml
server:
  port: 8080

storage:
  path: "./tokens"

security:
  api_key: "your-secret-key"  # Or set WEBAUTHN_MCP_API_KEY env var
```

## HTTP API

### Token Management

#### Create Token
```bash
POST /api/token
Content-Type: application/json

{
  "name": "My Test Token"
}
```

#### List Tokens
```bash
GET /api/token
```

#### Get Token Info
```bash
GET /api/token/:id
```

#### Delete Token
```bash
DELETE /api/token/:id
```

### Credential Management

#### List Credentials
```bash
GET /api/token/:id/credentials
```

#### Delete Credential
```bash
DELETE /api/token/:id/credentials/:credId
```

### WebAuthn Operations

#### Registration

Generate a WebAuthn registration response:

```bash
POST /api/token/:id/register
Content-Type: application/json

{
  "request": {
    "challenge": "base64url-encoded-challenge",
    "rp": {
      "id": "example.com",
      "name": "Example Corp"
    },
    "user": {
      "id": "base64url-encoded-user-id",
      "name": "user@example.com",
      "displayName": "User Name"
    },
    "attestation": "none",
    "residentKey": "required"
  },
  "overrides": {
    "user_verification": false,
    "backup_eligible": true,
    "aaguid": "84CVQH8UScGos4-BOyJVQQ"
  }
}
```

**Override Options:**
- `origin` - Custom origin (default: `https://{rp.id}`)
- `rp_id` - Override RP ID
- `user_verification` - Set UV flag (default: true)
- `user_present` - Set UP flag (default: true)
- `backup_eligible` - Set BE flag (default: false)
- `backup_state` - Set BS flag (default: false)
- `counter` - Set signature counter (default: 0)
- `aaguid` - Set AAGUID (base64url, 16 bytes, default: all zeros)
- `attestation_type` - "none" or "packed" (default: "none")
- `transport` - Array of transports (default: ["internal"])
- `invalid_signature` - Generate invalid signature for testing (default: false)
- `extensions` - Client extension results

#### Authentication

Generate a WebAuthn authentication response:

```bash
POST /api/token/:id/authenticate
Content-Type: application/json

{
  "credential_id": "base64url-credential-id",
  "request": {
    "challenge": "base64url-encoded-challenge",
    "rpId": "example.com",
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "base64url-credential-id"
      }
    ]
  },
  "overrides": {
    "user_verification": false,
    "counter": 42
  }
}
```

**Override Options:**
- `origin` - Custom origin
- `rp_id` - Override RP ID
- `user_verification` - Set UV flag
- `user_present` - Set UP flag
- `counter` - Set signature counter
- `invalid_signature` - Generate invalid signature
- `wrong_credential` - Use wrong credential ID
- `extensions` - Client extension results

## MCP Tools

When running as an MCP server, the following tools are available:

- `create_token` - Create a new soft token
- `delete_token` - Delete a token
- `list_tokens` - List all tokens
- `get_token_info` - Get token details
- `list_credentials` - List credentials for a token
- `delete_credential` - Delete a credential
- `register` - Generate registration response
- `authenticate` - Generate authentication response

## Use Cases

### Penetration Testing

Test WebAuthn implementations for security vulnerabilities:
- Invalid signature handling
- Counter rollback detection
- Origin validation
- RP ID validation
- User verification bypass

### Automated Testing

Integrate into CI/CD pipelines to test WebAuthn flows without physical authenticators.

### Development

Develop and debug WebAuthn implementations without needing multiple physical security keys.

## Project Structure

```
.
├── config/              # Configuration management
├── internal/
│   ├── api/            # HTTP API (Gin framework)
│   ├── mcp/            # MCP server implementation
│   ├── token/          # Token and credential storage
│   └── webauthn/       # WebAuthn response generation
├── tokens/             # JSON storage for tokens
├── config.yaml         # Configuration file
└── main.go            # Entry point
```

## Security Considerations

⚠️ **This tool is for testing purposes only!**

- Do not use in production environments
- Generated credentials are stored in plain JSON files
- Private keys are stored unencrypted
- No rate limiting or authentication by default
- Intended for controlled testing environments only

## Examples

### Example 1: Basic Registration

```bash
# Create a token
curl -X POST http://localhost:8080/api/token \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Token"}'

# Register a credential
curl -X POST http://localhost:8080/api/token/{token-id}/register \
  -H "Content-Type: application/json" \
  -d '{
    "request": {
      "challenge": "randomChallenge123",
      "rp": {"id": "example.com", "name": "Example"},
      "user": {"id": "user123", "name": "test@example.com", "displayName": "Test User"},
      "attestation": "none",
      "residentKey": "required"
    }
  }'
```

### Example 2: Simulate Hardware Security Key

```bash
# Register with hardware security key characteristics
curl -X POST http://localhost:8080/api/token/{token-id}/register \
  -H "Content-Type: application/json" \
  -d '{
    "request": {
      "challenge": "randomChallenge123",
      "rp": {"id": "example.com", "name": "Example"},
      "user": {"id": "user123", "name": "test@example.com", "displayName": "Test User"},
      "attestation": "none",
      "residentKey": "required"
    },
    "overrides": {
      "user_verification": false,
      "backup_eligible": true,
      "aaguid": "84CVQH8UScGos4-BOyJVQQ"
    }
  }'
```

### Example 3: Test Invalid Signature

```bash
# Generate authentication with invalid signature
curl -X POST http://localhost:8080/api/token/{token-id}/authenticate \
  -H "Content-Type: application/json" \
  -d '{
    "credential_id": "credential-id-here",
    "request": {
      "challenge": "randomChallenge456",
      "rpId": "example.com"
    },
    "overrides": {
      "invalid_signature": true
    }
  }'
```

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Disclaimer

This tool is provided for educational and testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations when using this tool.
