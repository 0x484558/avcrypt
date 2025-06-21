/*
 * avcrypt - Secure file encryption using Avtor SecureToken-338S
 * Copyright (C) 2025  Vladyslav "Hex" Yamkovyi <hex@aleph0.ai>
 * 
 * Licensed under the EUPL v1.2
 * 
 * This software is distributed under the terms of the European Union
 * Public Licence (EUPL) v1.2. You may obtain a copy of the licence at:
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 */

use zeroize::ZeroizeOnDrop;

pub mod app;
pub mod crypto;
pub mod files;
pub mod info;
pub mod keys;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CryptoAlgorithm {
    RsaAesCbc = 0,
    RsaAesGcm = 1,
}

#[derive(ZeroizeOnDrop)]
pub struct SecurePin {
    #[zeroize(drop)]
    pub pin: String,
}

#[derive(ZeroizeOnDrop)]
pub struct SecureKey {
    #[zeroize(drop)]
    pub key: Vec<u8>,
}

pub struct TokenCapabilities {
    pub has_rng: bool,
    pub has_aes_keygen: bool,
    pub has_aes_cbc: bool,
    pub has_aes_cbc_pad: bool,
    pub has_aes_gcm: bool,
    pub has_sha256: bool,
    pub has_sha512: bool,
    pub has_hmac_sha256: bool,
    pub max_session_count: u64,
    pub total_memory: u64,
    pub free_memory: u64,
}

pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// File signature to identify avcrypt files.
/// The trailing null byte is intentional to facilitate reading it as a C string.
pub const FILE_MAGIC: &[u8; 8] = b"avcrypt\0";
pub const FILE_VERSION: u8 = 1;

pub const AES_KEY_SIZE: usize = 32;
pub const AES_BLOCK_SIZE: usize = 16;
pub const GCM_IV_SIZE: usize = 12;
pub const GCM_TAG_SIZE: usize = 16;
pub const RSA_KEY_SIZE: usize = 512;
pub const CHUNK_SIZE: usize = 1024 * 1024;
pub const SHA256_SIZE: usize = 32;
pub const SHA512_SIZE: usize = 64;
