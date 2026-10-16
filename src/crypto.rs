//! ChaCha20Poly1305 encrypt/decrypt on BytesMut + HKDF-SHA256 key derivation.
//!
//! Encrypt/decrypt operate in place on a `BytesMut` via the aead 0.6 `AeadInOut`
//! detached APIs so the hot path never allocates a plaintext/ciphertext copy.

use bytes::Buf;
use bytes::BytesMut;
use chacha20poly1305::AeadInOut;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::KeyInit;
use chacha20poly1305::Nonce;
use chacha20poly1305::Tag;
use hkdf::Hkdf;
use rand::RngExt;
use sha2::Sha256;

use crate::constants::CHACHA20_NONCE_SIZE;
use crate::constants::CHACHA20POLY1305_AUTH_OVERHEAD;
use crate::error::EncryptionError;

/// Encrypts plaintext in `buf` in-place using ChaCha20Poly1305.
///
/// Layout after encryption: `[nonce:12][ciphertext:len(plaintext)][tag:16]`
/// Total output length = 12 + len(plaintext) + 16.
///
/// Zero-alloc: capacity is reserved up front and the plaintext is shifted in
/// place, so no intermediate buffer is allocated.
pub fn encrypt_in_place(
    buf: &mut BytesMut,
    key: &[u8; 32],
) -> Result<(), EncryptionError> {
    let plaintext_len = buf.len();

    // Reserve the fixed wire overhead (nonce + tag) so the resize below never
    // reallocates. The plaintext already occupies `plaintext_len` bytes.
    buf.reserve(CHACHA20_NONCE_SIZE + CHACHA20POLY1305_AUTH_OVERHEAD);

    // Generate a random 12-byte nonce.
    let nonce_bytes: [u8; CHACHA20_NONCE_SIZE] = rand::rng().random();
    let nonce = Nonce::from(nonce_bytes);

    let key_arr = chacha20poly1305::Key::try_from(&key[..])
        .map_err(|_| EncryptionError::EncryptionFailed)?;
    let cipher = ChaCha20Poly1305::new(&key_arr);

    // Grow to the final size, then shift the plaintext right by the nonce length to
    // make room for the nonce prefix. `copy_within` handles the overlapping move.
    buf.resize(
        CHACHA20_NONCE_SIZE + plaintext_len + CHACHA20POLY1305_AUTH_OVERHEAD,
        0,
    );
    buf.copy_within(0..plaintext_len, CHACHA20_NONCE_SIZE);
    buf[..CHACHA20_NONCE_SIZE].copy_from_slice(&nonce_bytes);

    // Encrypt the plaintext region in place -> ciphertext; receive the detached tag.
    let tag = cipher
        .encrypt_inout_detached(
            &nonce,
            &[],
            (&mut buf
                [CHACHA20_NONCE_SIZE..CHACHA20_NONCE_SIZE + plaintext_len])
                .into(),
        )
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    // Write the tag into the trailing bytes.
    buf[CHACHA20_NONCE_SIZE + plaintext_len..].copy_from_slice(&tag);

    debug_assert_eq!(
        buf.len(),
        CHACHA20_NONCE_SIZE + plaintext_len + CHACHA20POLY1305_AUTH_OVERHEAD
    );

    Ok(())
}

/// Decrypts ciphertext in `buf` in-place using ChaCha20Poly1305.
///
/// Expects layout: `[nonce:12][ciphertext][tag:16]`
/// On success, `buf` contains only the decrypted plaintext.
///
/// On failure the contents of `buf` are unspecified (the ciphertext region may have
/// been partially transformed); callers must discard the buffer on error.
pub fn decrypt_in_place(
    buf: &mut BytesMut,
    key: &[u8; 32],
) -> Result<(), EncryptionError> {
    // Minimum valid size: nonce + tag with an empty ciphertext.
    if buf.len() < CHACHA20_NONCE_SIZE + CHACHA20POLY1305_AUTH_OVERHEAD {
        return Err(EncryptionError::DecryptionFailed);
    }

    // Copy out the fixed-size nonce prefix and trailing tag (no borrow is held).
    let nonce_bytes: [u8; CHACHA20_NONCE_SIZE] = buf[..CHACHA20_NONCE_SIZE]
        .try_into()
        .map_err(|_| EncryptionError::DecryptionFailed)?;
    let tag_start = buf.len() - CHACHA20POLY1305_AUTH_OVERHEAD;
    let tag_bytes: [u8; CHACHA20POLY1305_AUTH_OVERHEAD] = buf[tag_start..]
        .try_into()
        .map_err(|_| EncryptionError::DecryptionFailed)?;
    let nonce = Nonce::from(nonce_bytes);
    let tag = Tag::from(tag_bytes);

    let key_arr = chacha20poly1305::Key::try_from(&key[..])
        .map_err(|_| EncryptionError::DecryptionFailed)?;
    let cipher = ChaCha20Poly1305::new(&key_arr);

    // Ciphertext occupies [nonce_len, len - tag_len); decrypt it in place.
    let ct_end = buf.len() - CHACHA20POLY1305_AUTH_OVERHEAD;
    cipher
        .decrypt_inout_detached(
            &nonce,
            &[],
            (&mut buf[CHACHA20_NONCE_SIZE..ct_end]).into(),
            &tag,
        )
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    // On success, strip the trailing tag and the nonce prefix, leaving the plaintext.
    buf.truncate(ct_end);
    buf.advance(CHACHA20_NONCE_SIZE);

    Ok(())
}

/// Derives a 32-byte key from a password and client ID using HKDF-SHA256.
///
/// Salt: `b"ping-tunnel-v1"`, info: `client_id`.
/// The 32-byte expansion from SHA-256 is infallible per HKDF spec (§2.3).
#[allow(clippy::expect_used)] // hk.expand to 32 bytes is infallible; see note below.
pub fn derive_key(password: &str, client_id: &[u8; 16]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"ping-tunnel-v1"), password.as_bytes());
    let mut okm = [0u8; 32];
    // Maximum OKM length from HKDF-SHA256 is 255*32 = 8160 bytes;
    // 32-byte output is guaranteed to succeed.
    hk.expand(client_id, &mut okm)
        .expect("HKDF-SHA256 expand to 32 bytes must not fail");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42; 32];
        let plaintext = b"hello world";
        let mut buf = BytesMut::from(&plaintext[..]);

        encrypt_in_place(&mut buf, &key).unwrap();
        assert!(buf.len() > plaintext.len());
        assert_eq!(buf.len(), 12 + plaintext.len() + 16);

        decrypt_in_place(&mut buf, &key).unwrap();
        assert_eq!(buf.as_ref(), plaintext);
    }

    #[test]
    fn test_wrong_key() {
        let key_a = [0xAA; 32];
        let key_b = [0xBB; 32];
        let mut buf = BytesMut::from(&b"secret message"[..]);

        encrypt_in_place(&mut buf, &key_a).unwrap();
        let result = decrypt_in_place(&mut buf, &key_b);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered() {
        let key = [0x42; 32];
        let mut buf = BytesMut::from(&b"tamper test"[..]);

        encrypt_in_place(&mut buf, &key).unwrap();

        // Flip a byte in the ciphertext region (after nonce)
        let flip_idx = 13; // byte just after the nonce
        buf[flip_idx] ^= 0x01;

        let result = decrypt_in_place(&mut buf, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_deterministic() {
        let password = "correct-horse-battery-staple";
        let client = [0xAB; 16];

        let k1 = derive_key(password, &client);
        let k2 = derive_key(password, &client);

        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_different_client() {
        let password = "s3cr3t";
        let client_a = [0xAA; 16];
        let client_b = [0xBB; 16];

        let ka = derive_key(password, &client_a);
        let kb = derive_key(password, &client_b);

        assert_ne!(ka, kb);
    }

    #[test]
    fn test_encrypt_layout() {
        let key = [0x42; 32];
        let plaintext = b"layout check";
        let mut buf = BytesMut::from(&plaintext[..]);
        encrypt_in_place(&mut buf, &key).unwrap();

        // [nonce:12][ciphertext:plaintext_len][tag:16]
        assert_eq!(buf.len(), 12 + plaintext.len() + 16);

        // The nonce prefix differs across two encryptions of the same plaintext.
        let mut buf2 = BytesMut::from(&plaintext[..]);
        encrypt_in_place(&mut buf2, &key).unwrap();
        assert_ne!(&buf[..12], &buf2[..12]);

        // The trailing 16 bytes are the authentication tag: corrupting them fails
        // decryption, proving the tag occupies the tail of the buffer.
        let mut tampered_tag = buf.clone();
        let last = tampered_tag.len() - 1;
        tampered_tag[last] ^= 0x01;
        assert!(decrypt_in_place(&mut tampered_tag, &key).is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let key = [0x42; 32];
        // 27 bytes < nonce(12) + tag(16) = 28.
        let mut buf = BytesMut::from(&[0u8; 27][..]);
        let result = decrypt_in_place(&mut buf, &key);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn test_nonce_uniqueness() {
        let key = [0x42; 32];
        let plaintext = b"nonce reuse is catastrophic";

        let mut a = BytesMut::from(&plaintext[..]);
        let mut b = BytesMut::from(&plaintext[..]);
        encrypt_in_place(&mut a, &key).unwrap();
        encrypt_in_place(&mut b, &key).unwrap();

        // ChaCha20 nonce reuse would be catastrophic; guard the RNG path.
        assert_ne!(&a[..12], &b[..12]);
    }
}
