use ed25519_dalek::{
    Signature, SigningKey, VerifyingKey,
    PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, SignatureError,
    Signer,            
};
use rand::rngs::StdRng;
use rand::SeedableRng;

/// Public type aliases
pub type PublicKeyBytes = [u8; PUBLIC_KEY_LENGTH];
pub type SignatureBytes  = [u8; SIGNATURE_LENGTH];

#[derive(Debug, thiserror::Error)] 
pub enum CryptoError {
    #[error("signature verification failed")]
    BadSignature,
    #[error("input had wrong length")]
    LengthMismatch,
    #[error("dalek error: {0}")]
    Dalek(#[from] SignatureError),
}

/// Generate a fresh Ed25519 keypair
pub fn generate_keypair() -> (PublicKeyBytes, SigningKey) {
    let mut rng = StdRng::from_entropy();
    let sk = SigningKey::generate(&mut rng);
    let pk = sk.verifying_key().to_bytes();
    /// Return public key and secret key
    (pk, sk)
}

/// Signs message with secret key
pub fn sign(sk: &SigningKey, msg: &[u8]) -> SignatureBytes {
    sk.sign(msg).to_bytes()
}

/// Verifies a message + signature under a raw public key.
pub fn verify(pk: &PublicKeyBytes, msg: &[u8], signature: &SignatureBytes) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(pk)?;
    let signature = Signature::from_bytes(signature);
    vk.verify_strict(msg, &signature)
        .map_err(|_| CryptoError::BadSignature)
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_succeeds() {
        let (pk, sk) = generate_keypair();
        let msg = b"hello-world";
        let signature = sign(&sk, msg);
        assert!(verify(&pk, msg, &signature).is_ok());   
    }

    #[test]
    fn reject_tampered_message() {
        let (pk, sk) = generate_keypair();
        let signature = sign(&sk, b"good");
        let bad = verify(&pk, b"evil", &signature);
        assert!(matches!(bad, Err(CryptoError::BadSignature)));
    }
}