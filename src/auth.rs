//! Encrypted authentication handshake between client and server.
//!
//! A client proves its identity by sending `[client_id][AUTH_MAGIC]` encrypted with a
//! key derived from its password. The server trial-decrypts against every allowed key;
//! a match identifies the client. All subsequent data packets carry the client id in
//! plaintext for O(1) routing.

use std::collections::BTreeMap;

use bytes::BytesMut;

use crate::ClientId;
use crate::constants::AUTH_MAGIC;
use crate::constants::AUTH_REJECT_OCTET;
use crate::constants::CLIENT_ID_BYTES;
use crate::constants::SESSION_EXPIRED_OCTET;
use crate::crypto;
use crate::error::EncryptionError;

const AUTH_REQUEST_LEN: usize = CLIENT_ID_BYTES + 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthGrant {
    pub client_id: ClientId,
    pub key: [u8; 32],
    pub tun_octet: u8,
}

/// Builds an encrypted auth-request packet.
///
/// The plaintext `[client_id:16][AUTH_MAGIC:1]` is encrypted in-place with a key
/// derived from `password` + `client_id`. Output layout:
/// `[nonce:12][ciphertext:17][tag:16]`.
pub fn build_auth_packet(
    client_id: &ClientId,
    password: &str,
) -> Result<BytesMut, EncryptionError> {
    let key = crypto::derive_key(password, client_id.0.as_bytes());
    let mut buf = BytesMut::with_capacity(AUTH_REQUEST_LEN);
    buf.extend_from_slice(client_id.0.as_bytes());
    buf.extend_from_slice(&[AUTH_MAGIC]);
    crypto::encrypt_in_place(&mut buf, &key)?;
    Ok(buf)
}

/// Trial-decrypts an incoming auth request against every key in the allowlist.
///
/// Each candidate is tried against a fresh copy of `buf` (`BytesMut::clone`
/// copies). A candidate matches when decryption succeeds AND the plaintext is exactly
/// [`AUTH_REQUEST_LEN`] bytes with the `client_id` prefix matching the candidate and the
/// trailing [`AUTH_MAGIC`] byte intact.
///
/// Returns `Ok(None)` when no key matches (or the server is full).
pub fn server_try_auth(
    buf: &mut BytesMut,
    allowlist: &BTreeMap<ClientId, [u8; 32]>,
    tun_octet_alloc: &mut impl FnMut() -> Option<u8>,
) -> Result<Option<AuthGrant>, EncryptionError> {
    for (client_id, key) in allowlist {
        let mut trial = buf.clone();
        if crypto::decrypt_in_place(&mut trial, key).is_err() {
            continue;
        }
        if trial.len() != AUTH_REQUEST_LEN {
            continue;
        }
        let expected_id = client_id.0.as_bytes();
        if trial[..CLIENT_ID_BYTES] != expected_id[..] {
            continue;
        }
        if trial[AUTH_REQUEST_LEN - 1] != AUTH_MAGIC {
            continue;
        }

        let Some(tun_octet) = tun_octet_alloc() else {
            return Ok(None);
        };
        return Ok(Some(AuthGrant {
            client_id: client_id.clone(),
            key: *key,
            tun_octet,
        }));
    }
    Ok(None)
}

/// Returns the first allowlist key that decrypts `buf`, regardless of whether the
/// plaintext validates as an auth request.
///
/// Used by the server to answer with [`build_auth_reject`] when a key matched but
/// validation failed (or the server is out of octets): only the holder of that key
/// can read the reject, which distinguishes "rejected" from "server gone".
pub fn trial_decrypt_key(
    buf: &BytesMut,
    allowlist: &BTreeMap<ClientId, [u8; 32]>,
) -> Option<[u8; 32]> {
    for key in allowlist.values() {
        let mut trial = buf.clone();
        if crypto::decrypt_in_place(&mut trial, key).is_ok() {
            return Some(*key);
        }
    }
    None
}

/// Builds an encrypted auth response carrying the assigned `tun_octet`.
///
/// Plaintext `[AUTH_MAGIC:1][tun_octet:1]`.
pub fn build_auth_response(
    key: &[u8; 32],
    tun_octet: u8,
) -> Result<BytesMut, EncryptionError> {
    let mut buf = BytesMut::with_capacity(2);
    buf.extend_from_slice(&[AUTH_MAGIC, tun_octet]);
    crypto::encrypt_in_place(&mut buf, key)?;
    Ok(buf)
}

/// Builds an encrypted auth rejection.
///
/// Plaintext `[AUTH_MAGIC:1][AUTH_REJECT_OCTET:1]` so a client holding the right key can
/// distinguish "rejected" (well-formed, sentinel octet) from "server gone" (garbage fails
/// to decrypt).
pub fn build_auth_reject(key: &[u8; 32]) -> Result<BytesMut, EncryptionError> {
    let mut buf = BytesMut::with_capacity(2);
    buf.extend_from_slice(&[AUTH_MAGIC, AUTH_REJECT_OCTET]);
    crypto::encrypt_in_place(&mut buf, key)?;
    Ok(buf)
}

/// Builds an encrypted session-expiry notice.
///
/// Plaintext `[AUTH_MAGIC:1][SESSION_EXPIRED_OCTET:1]`. The server sends it when
/// it dropped a session (client inactivity): only the holder of that client's key
/// can read it, and it tells the client to authenticate again. Unlike a
/// credentials reject it is not a verdict, so a client that receives one while it
/// is already re-authenticating ignores it.
pub fn build_session_expired(
    key: &[u8; 32],
) -> Result<BytesMut, EncryptionError> {
    let mut buf = BytesMut::with_capacity(2);
    buf.extend_from_slice(&[AUTH_MAGIC, SESSION_EXPIRED_OCTET]);
    crypto::encrypt_in_place(&mut buf, key)?;
    Ok(buf)
}

/// Decrypts an auth response and extracts the tun octet.
pub fn parse_auth_response(
    buf: &mut BytesMut,
    key: &[u8; 32],
) -> Result<u8, EncryptionError> {
    crypto::decrypt_in_place(buf, key)?;
    if buf.len() != 2 {
        return Err(EncryptionError::DecryptionFailed);
    }
    if buf[0] != AUTH_MAGIC {
        return Err(EncryptionError::DecryptionFailed);
    }
    match buf[1] {
        AUTH_REJECT_OCTET => Err(EncryptionError::AuthRejected),
        SESSION_EXPIRED_OCTET => Err(EncryptionError::SessionExpired),
        tun_octet => Ok(tun_octet),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_auth() {
        let client_id = ClientId(uuid::Uuid::nil());
        let password = "correct-horse-battery-staple";
        let key = crypto::derive_key(password, client_id.0.as_bytes());

        let mut packet = build_auth_packet(&client_id, password).unwrap();

        let mut allowlist = BTreeMap::new();
        allowlist.insert(client_id.clone(), key);

        let grant = server_try_auth(&mut packet, &allowlist, &mut || Some(5u8))
            .unwrap()
            .expect("auth should match");

        assert_eq!(grant.client_id, client_id);
        assert_eq!(grant.tun_octet, 5);
    }

    #[test]
    fn test_wrong_password() {
        let client_id = ClientId(uuid::Uuid::nil());
        let password_a = "password-alpha";
        let password_b = "password-bravo";

        let mut packet = build_auth_packet(&client_id, password_a).unwrap();

        let key_b = crypto::derive_key(password_b, client_id.0.as_bytes());
        let mut allowlist = BTreeMap::new();
        allowlist.insert(client_id, key_b);

        let result =
            server_try_auth(&mut packet, &allowlist, &mut || Some(5u8))
                .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_unknown_client() {
        let client_a = ClientId(uuid::Uuid::nil());
        let client_b = ClientId(uuid::Uuid::max());
        let password = "s3cr3t";

        let mut packet = build_auth_packet(&client_a, password).unwrap();

        let key_b = crypto::derive_key(password, client_b.0.as_bytes());
        let mut allowlist = BTreeMap::new();
        allowlist.insert(client_b, key_b);

        let result =
            server_try_auth(&mut packet, &allowlist, &mut || Some(5u8))
                .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_response_roundtrip() {
        let key = [0x42u8; 32];
        let tun_octet = 5u8;

        let mut response = build_auth_response(&key, tun_octet).unwrap();
        let parsed = parse_auth_response(&mut response, &key).unwrap();
        assert_eq!(parsed, tun_octet);
    }

    #[test]
    fn test_bad_marker_errors() {
        let key = [0x42u8; 32];
        // A well-formed 2-byte response whose marker is not AUTH_MAGIC is rejected,
        // not parsed (and never panics).
        let mut buf = BytesMut::from(&[0x02u8, 7u8][..]);
        crypto::encrypt_in_place(&mut buf, &key).unwrap();
        let result = parse_auth_response(&mut buf, &key);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn test_auth_response_reject_builder() {
        let key = [0x42u8; 32];
        let mut response = build_auth_reject(&key).unwrap();
        let result = parse_auth_response(&mut response, &key);
        assert!(matches!(result, Err(EncryptionError::AuthRejected)));
    }

    #[test]
    fn test_session_expiry_notice() {
        let key = [0x42u8; 32];
        let mut notice = build_session_expired(&key).unwrap();
        assert!(matches!(
            parse_auth_response(&mut notice, &key),
            Err(EncryptionError::SessionExpired)
        ));

        // The two server notices stay distinguishable: a credentials reject is
        // fatal for the client, an expiry notice is not.
        let mut reject = build_auth_reject(&key).unwrap();
        assert!(matches!(
            parse_auth_response(&mut reject, &key),
            Err(EncryptionError::AuthRejected)
        ));
    }

    #[test]
    fn test_auth_response_garbage() {
        let key = [0x42u8; 32];
        // A 30-byte garbage buffer is not a valid ciphertext (or a 2-byte response),
        // so parsing it errors rather than panicking.
        let mut garbage = BytesMut::from(&[0x55u8; 30][..]);
        let result = parse_auth_response(&mut garbage, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_trial_decrypt_key() {
        let client_id = ClientId(uuid::Uuid::nil());
        let key = crypto::derive_key("pw", client_id.0.as_bytes());
        let mut allowlist = BTreeMap::new();
        allowlist.insert(client_id.clone(), key);

        // A well-formed auth request identifies its key...
        let packet = build_auth_packet(&client_id, "pw").unwrap();
        assert_eq!(trial_decrypt_key(&packet, &allowlist), Some(key));

        // ...and so does a malformed message under a valid key (wrong message
        // type here), so the server can reject instead of dropping silently.
        let malformed = build_auth_response(&key, 5).unwrap();
        assert_eq!(trial_decrypt_key(&malformed, &allowlist), Some(key));

        // Random bytes decrypt under no key.
        let garbage = BytesMut::from(&[0x55u8; 30][..]);
        assert_eq!(trial_decrypt_key(&garbage, &allowlist), None);
    }

    #[test]
    fn test_auth_request_rejects_truncated_plaintext() {
        // A 16-byte plaintext (client id only, no AUTH_MAGIC) decrypts under the right
        // key but is not a valid request: the server rejects it rather than granting.
        let client_id = ClientId(uuid::Uuid::nil());
        let password = "pw";
        let key = crypto::derive_key(password, client_id.0.as_bytes());

        let mut allowlist = BTreeMap::new();
        allowlist.insert(client_id.clone(), key);

        let mut packet = BytesMut::new();
        packet.extend_from_slice(client_id.0.as_bytes());
        crypto::encrypt_in_place(&mut packet, &key).unwrap();

        let result =
            server_try_auth(&mut packet, &allowlist, &mut || Some(2u8))
                .unwrap();
        assert!(result.is_none());
    }
}
