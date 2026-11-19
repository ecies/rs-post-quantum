use core::fmt;

/// Why encryption, decryption or key generation failed
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The public key has the wrong length for the ML-KEM parameter set, or fails its modulus check
    InvalidPublicKey,
    /// The secret key is neither a 64 bytes seed nor an expanded key of the right length, or fails its hash check
    InvalidSecretKey,
    /// The payload is too short, was not encrypted to this key and config, or was tampered with.
    /// When encrypting, the message is too long for the symmetric cipher.
    InvalidMessage,
    /// The system random number generator failed
    RngFailure,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidPublicKey => "invalid public key",
            Error::InvalidSecretKey => "invalid secret key",
            Error::InvalidMessage => "invalid message",
            Error::RngFailure => "random number generator failed",
        })
    }
}

impl core::error::Error for Error {}
