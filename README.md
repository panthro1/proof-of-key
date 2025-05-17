# Proof-of-Key demo (Rust)

A minimal system that proves a client controls an Ed25519 private key without ever revealing it.

## Crates
| crate      | role                                         |
|------------|----------------------------------------------|
| `crypto`   | keygen, sign, verify (unit-tested)           |
| `verifier` | Axum web service (`/nonce`, `/attest`)       |
| `holder`   | CLI tool that stores a keypair and signs nonces |

## Quick start

```bash
# 1. start the verifier
cd proof-of-key-main
cargo run --bin verifier    # listens on 127.0.0.1:8080

# 2. generate a holder keypair (one-time)
cargo run --bin holder -- generate-key

# 3. end-to-end proof
NONCE=$(curl -s -X POST 127.0.0.1:8080/nonce | jq -r '.nonce')
cargo run --quiet --bin holder -- sign "$NONCE" > att.json
curl -i -X POST 127.0.0.1:8080/attest \
     -H "Content-Type: application/json" \
     --data-binary @att.json   # → HTTP/1.1 204 No Content
```

## Requirements
- Rust (latest stable)

## Notes
- The holder's keypair is stored at `~/.config/proof-of-key/ed25519.key`.
- The attestation file (`att.json`) is a temporary artifact for demo/testing.
- The verifier will only accept fresh nonces to prevent replay attacks.

## License
MIT
