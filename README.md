# NFCGate Server
This is the NFCGate server application using Python 3 and the Google [Protobuf](https://github.com/google/protobuf/) library, version 3.

To run, simply start the server using `python server.py`. You can then connect to the server using the IP address of your device and the default port of 5566.  
The server features a plugin system for data filtering. When starting the server, you can specify a list of plugins to be loaded as parameters, e.g. `python server.py log`. For an example, see the shipped `mod_log.py` plugin.

## TLS Support

The server supports TLS (WSS) connections for secure communication:

```bash
python server.py --tls --tls_cert /path/to/cert.pem --tls_key /path/to/key.pem
```

## Authentication

The server now supports optional authentication via HMAC challenge-response to protect against unauthorized access when deployed publicly.

### Features

- **HMAC-based challenge-response authentication** using SHA-256
- **Session management** with configurable TTL
- **Rate limiting** to prevent brute-force attacks
- **TLS enforcement** (authentication only works over secure connections by default)
- **Backward compatible** - disabled by default

### Configuration

Authentication is configured via environment variables:

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ENABLE_AUTHENTICATION` | bool | `false` | Enable authentication handshake |
| `NFCGATE_SECRET` | string | `""` | Shared secret for HMAC verification (required when auth enabled) |
| `SESSION_TTL_SECONDS` | int | `3600` | Session time-to-live in seconds (default: 1 hour) |
| `ALLOW_PLAINTEXT_AUTH` | bool | `false` | Allow auth over non-TLS connections (NOT RECOMMENDED) |

### Usage

**Basic setup with TLS and authentication:**

```bash
# Set the shared secret
export NFCGATE_SECRET="your_strong_secret_here"
export ENABLE_AUTHENTICATION=true

# Run server with TLS
python server.py --tls --tls_cert cert.pem --tls_key key.pem
```

**Development/testing without TLS (insecure):**

```bash
export NFCGATE_SECRET="test_secret"
export ENABLE_AUTHENTICATION=true
export ALLOW_PLAINTEXT_AUTH=true  # WARNING: Only for testing!

python server.py
```

### Authentication Flow

1. Client connects to server
2. If authentication is enabled:
   - Server sends `AuthChallenge` with a random nonce
   - Client computes `HMAC-SHA256(secret, nonce)` and sends `AuthResponse`
   - Server verifies the HMAC
   - On success: Server sends `AuthResult` with `session_id` and allows communication
   - On failure: Server sends `AuthResult` with error reason and closes connection
3. All subsequent messages must come from authenticated clients

### Security Notes

- **Never log or expose the secret** - it's stored only in environment variables
- **Use strong secrets** - generate with: `python -c "import secrets; print(secrets.token_hex(32))"`
- **Always use TLS in production** - plaintext auth is for testing only
- **Rate limiting** - 5 failed attempts per IP per 60 seconds
- **Session expiry** - sessions automatically expire after TTL

### Protocol Definition

Authentication messages are defined in `protocol/protobuf/auth.proto`:

```protobuf
message AuthChallenge {
    string nonce = 1;
}

message AuthResponse {
    string client_id = 1;
    string hmac = 2;  // hex string of HMAC-SHA256(secret, nonce)
}

message AuthResult {
    bool success = 1;
    string session_id = 2;  // populated on success
    string reason = 3;       // populated on failure
}
```

### Generating Protobuf Code

If you modify `auth.proto`, regenerate the Python code:

```bash
# Linux/Mac
./make_proto.sh

# Windows (or manual)
protoc -I=protocol/protobuf --python_out=plugins protocol/protobuf/auth.proto
```
