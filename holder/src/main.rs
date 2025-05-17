//! holder CLI: generates one Ed25519 keypair and signs verifier nonces.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use crypto::{generate_keypair, sign, PublicKeyBytes, SignatureBytes};
use ed25519_dalek::SigningKey;
use serde::Serialize;
use serde_json;
use std::{fs, path::PathBuf};
use uuid::Uuid;

/// key lives at ~/.config/proof-of-key/ed25519.key
const APP_DIR: &str = "proof-of-key"; // application subfolder in the user config directory
const KEY_FILE: &str = "ed25519.key"; // filename stored
const KEY_BYTES: usize = 64; // 32-byte secret + 32-byte public

/// CLI definition 
#[derive(Parser)]
#[command(name = "holder", about = "Proof-of-key holder CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate and save a fresh Ed25519 keypair
    GenerateKey,
    /// Sign a verifier nonce (UUID string) and emit JSON to stdout
    Sign {
        // Nonce obtained from POST /nonce
        nonce: String,
    },
}

/// JSON payload
#[derive(Serialize)]
struct Attestation<'a> {
    nonce: &'a str,
    public_key: String,
    signature: String,
}

/// Returns the absolute path to the key file, creating the
/// `~/.config/proof-of-key` directory if it does not yet exist.
fn key_path() -> Result<PathBuf> {
    let mut directory = dirs::config_dir().ok_or_else(|| anyhow!("no config directory"))?;
    directory.push(APP_DIR);
    fs::create_dir_all(&directory)?;
    directory.push(KEY_FILE);
    Ok(directory)
}

/// Reads the on-disk Base64 blob, verifies its length,
/// and reconstructs the `(public, secret)` Ed25519 keypair.
fn load_keypair() -> Result<(PublicKeyBytes, SigningKey)> {
    let encoded = fs::read(key_path()?)?;
    let bytes   = STANDARD.decode(encoded)?;
    if bytes.len() != KEY_BYTES {
        return Err(anyhow!("corrupt key file"));
    }
    
    // split and convert into fixed-size arrays
    let secret: [u8; 32]        = bytes[..32].try_into().unwrap();
    let public: PublicKeyBytes  = bytes[32..].try_into().unwrap();
    Ok((public, SigningKey::from_bytes(&secret)))
}

/// main
fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::GenerateKey => {
            let (pk, sk) = generate_keypair();

            // secret || public  → base64
            let mut blob = Vec::with_capacity(KEY_BYTES);
            blob.extend_from_slice(sk.to_bytes().as_slice()); // 32 bytes
            blob.extend_from_slice(&pk);                      // 32 bytes
            fs::write(key_path()?, STANDARD.encode(blob))?;

            println!("✅  Keypair written to {}", key_path()?.display());
        }

        Cmd::Sign { nonce } => {
            // validate nonce format
            Uuid::parse_str(&nonce)
                .map_err(|_| anyhow!("nonce must be a valid UUID (got {nonce})"))?;

            // load keypair
            let (pk, sk) = load_keypair()?;

            // sign the nonce bytes
            let sig: SignatureBytes = sign(&sk, nonce.as_bytes());

            // emit JSON attestation
            let att = Attestation {
                nonce: &nonce,
                public_key: STANDARD.encode(pk),
                signature:  STANDARD.encode(sig),
            };
            // print attestation as JSON to att.json as a temporary artifact for testing the proof flow
            println!("{}", serde_json::to_string(&att)?);
        }
    }

    Ok(())
}