# WebAuthn MCP

A WebAuthn soft token simulator for penetration testing and automated testing.

## Tools

### Token Management

- **create_token**: Create a new WebAuthn soft token
- **delete_token**: Delete a token
- **list_tokens**: List all tokens
- **get_token_info**: Get token details
- **list_credentials**: List credentials in a token
- **delete_credential**: Delete a credential

### WebAuthn Operations

- **register**: Generate a WebAuthn registration response
  - Supports both resident key and non-resident key modes
  - Configurable attestation (none, packed)
  - Override origin, rpId, flags, counter for testing

- **authenticate**: Generate a WebAuthn authentication response
  - Supports resident key lookup by RP ID
  - Can generate invalid signatures for testing
  - Override counter, flags, return wrong credential ID

## Use Cases

1. **Penetration Testing**: Test WebAuthn server implementations by sending crafted responses
2. **Automated Testing**: Integrate with test frameworks like Strix or Shannon
3. **Security Research**: Explore WebAuthn edge cases and vulnerabilities

## Override Options

### Registration Overrides
- `origin`: Override the origin in clientDataJSON
- `rp_id`: Override the RP ID in authenticator data
- `user_verification`: Override UV flag (true/false)
- `user_present`: Override UP flag (true/false)
- `counter`: Set specific counter value
- `attestation_type`: Force attestation type (none/packed)
- `transport`: Set transports (usb, nfc, ble, internal)
- `invalid_signature`: Generate an invalid signature

### Authentication Overrides
- `origin`: Override the origin in clientDataJSON
- `rp_id`: Override the RP ID in authenticator data
- `user_verification`: Override UV flag
- `user_present`: Override UP flag
- `counter`: Set specific counter value (0 for replay attack testing)
- `invalid_signature`: Generate an invalid signature
- `wrong_credential`: Return a different credential ID

## Example Usage

```
// Create a token
create_token name="test-token"

// Register with a challenge
register token_id="..." challenge="..." rp_id="example.com" user_id="..." user_name="test@example.com"

// Authenticate with overrides for testing
authenticate token_id="..." challenge="..." rp_id="example.com" user_verification=false counter=0
```
