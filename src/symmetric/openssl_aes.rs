use openssl::symm::{Cipher, Crypter, Mode};

use alloc::vec::Vec;

const KEY_LENGTH: usize = 32;
const TAG_LENGTH: usize = 16;
/// rust-openssl panics on more than `i32::MAX` bytes in one call, so longer messages go through in chunks
const CHUNK_LENGTH: usize = 1 << 30;

/// OpenSSL AES-256-GCM encryption, appending `nonce || tag || encrypted` to `output`.
///
/// On failure, `output` is left as it was.
pub(super) fn encrypt_into(output: &mut Vec<u8>, key: &[u8], nonce: &[u8], plain: &[u8]) -> Option<()> {
    if key.len() != KEY_LENGTH {
        return None;
    }
    let mut crypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Encrypt, key, Some(nonce)).ok()?;

    let base = output.len();
    let tag_start = base + nonce.len();
    output.reserve(nonce.len() + TAG_LENGTH + plain.len());
    output.extend_from_slice(nonce);
    output.resize(tag_start + TAG_LENGTH + plain.len(), 0);

    let (tag, encrypted) = output[tag_start..].split_at_mut(TAG_LENGTH);
    let result = update_all(&mut crypter, plain, encrypted)
        .and_then(|()| finalize(&mut crypter))
        .and_then(|()| crypter.get_tag(tag).ok());
    if result.is_none() {
        output.truncate(base);
    }
    result
}

/// OpenSSL AES-256-GCM decryption of a `nonce || tag || encrypted` payload
pub(super) fn decrypt(key: &[u8], nonce_length: usize, encrypted: &[u8]) -> Option<Vec<u8>> {
    if key.len() != KEY_LENGTH || encrypted.len() < nonce_length + TAG_LENGTH {
        return None;
    }

    let (nonce, rest) = encrypted.split_at(nonce_length);
    let (tag, encrypted) = rest.split_at(TAG_LENGTH);
    let mut crypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Decrypt, key, Some(nonce)).ok()?;

    let mut plain = alloc::vec![0u8; encrypted.len()];
    update_all(&mut crypter, encrypted, &mut plain)?;
    // the same order as rust-openssl's `decrypt_aead`: the tag goes in after the data, before finalizing
    crypter.set_tag(tag).ok()?;
    finalize(&mut crypter)?;
    Some(plain)
}

/// Runs `input` through the cipher into `output`, which has the same length
fn update_all(crypter: &mut Crypter, input: &[u8], output: &mut [u8]) -> Option<()> {
    for (input, output) in input.chunks(CHUNK_LENGTH).zip(output.chunks_mut(CHUNK_LENGTH)) {
        // AES-GCM writes exactly as many bytes as it reads
        if crypter.update(input, output).ok()? != input.len() {
            return None;
        }
    }
    Some(())
}

/// Finishes the cipher; for decryption, this is where the tag is checked
fn finalize(crypter: &mut Crypter) -> Option<()> {
    // AES-GCM has no bytes left to write, so its block size is 1 and it needs no output space
    crypter.finalize(&mut []).ok()?;
    Some(())
}
