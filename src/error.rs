#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("socket creation failed: {0}")]
    SocketCreate(std::io::Error),

    #[error("send failed: {0}")]
    Send(std::io::Error),

    #[error("receive failed: {0}")]
    Recv(std::io::Error),

    #[error("sysctl operation failed on {path}: {source}")]
    Sysctl { path: String, source: std::io::Error },
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("encryption failed")]
    EncryptionFailed,

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("authentication rejected by server")]
    AuthRejected,

    #[error("session expired: re-authentication required")]
    SessionExpired,
}
