use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag, array::typenum::Unsigned};

use alloc::vec::Vec;

/// Pure Rust AEAD encryption, appending `nonce || tag || encrypted` to `output`.
///
/// On failure, `output` is left as it was.
pub(super) fn encrypt_into<C: AeadInOut + KeyInit>(
    output: &mut Vec<u8>,
    key: &[u8],
    nonce: &[u8],
    plain: &[u8],
) -> Option<()> {
    let aead = C::new_from_slice(key).ok()?;
    let nonce = Nonce::<C>::try_from(nonce).ok()?;

    let base = output.len();
    let tag_start = base + nonce.len();
    let encrypted_start = tag_start + C::TagSize::USIZE;
    output.reserve(encrypted_start - base + plain.len());
    output.extend_from_slice(&nonce);
    output.resize(encrypted_start, 0);
    output.extend_from_slice(plain);

    match aead.encrypt_inout_detached(&nonce, &[], (&mut output[encrypted_start..]).into()) {
        Ok(tag) => {
            output[tag_start..encrypted_start].copy_from_slice(&tag);
            Some(())
        }
        Err(_) => {
            output.truncate(base);
            None
        }
    }
}

/// Pure Rust AEAD decryption of a `nonce || tag || encrypted` payload
pub(super) fn decrypt<C: AeadInOut + KeyInit>(key: &[u8], encrypted: &[u8]) -> Option<Vec<u8>> {
    let nonce_length = C::NonceSize::USIZE;
    let nonce_tag_length = nonce_length + C::TagSize::USIZE;
    if encrypted.len() < nonce_tag_length {
        return None;
    }

    let aead = C::new_from_slice(key).ok()?;
    let nonce = Nonce::<C>::try_from(&encrypted[..nonce_length]).ok()?;
    let tag = Tag::<C>::try_from(&encrypted[nonce_length..nonce_tag_length]).ok()?;

    let mut out = encrypted[nonce_tag_length..].to_vec();
    aead.decrypt_inout_detached(&nonce, &[], out.as_mut_slice().into(), &tag)
        .ok()?;
    Some(out)
}
