use core::fmt;

/// Reasons encryption, decryption, or key generation can fail.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The public key has the wrong length for the ML-KEM parameter set, or failed the FIPS 203 modulus check.
    InvalidPublicKey,
    /// The secret key is neither a 64-byte seed nor a valid-length expanded key, or failed the FIPS 203 hash check.
    InvalidSecretKey,
    /// During decryption: the payload is too short, tampered with, or encrypted for a different key or config.
    /// During encryption: the message exceeds the symmetric cipher's length limit.
    InvalidMessage,
    /// The system random number generator failed.
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
