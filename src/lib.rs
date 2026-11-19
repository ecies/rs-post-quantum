#![doc = include_str!("../README.md")]
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

/// Encryption configuration
pub mod config;
/// Constant values
pub mod consts;
/// Symmetric encryption/decryption
pub mod symmetric;
