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

use crate::{CryptoAlgorithm, FILE_MAGIC, FILE_VERSION};
use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[repr(C, packed)]
pub struct FileHeader {
    pub magic: [u8; 8],
    pub version: u8,
    crypto_algorithm: u8,
    flags: u16,
    timestamp: u64,
    pub original_file_size: u64,
    pub wrapped_enc_key_len: u16,
    pub wrapped_mac_key_len: u16,
    key_label: [u8; 32],
    pub iv_len: u8,
    pub tag_len: u8,
    file_hmac: [u8; 32],
    reserved: [u8; 4],
    header_hmac: [u8; 32],
}

impl FileHeader {
    pub fn new(
        file_size: u64,
        wrapped_enc_key_len: u16,
        wrapped_mac_key_len: u16,
        key_label: &str,
        iv_len: u8,
        algo: CryptoAlgorithm,
    ) -> Self {
        let mut label_bytes = [0u8; 32];
        let label_data = key_label.as_bytes();
        let copy_len = label_data.len().min(32);
        label_bytes[..copy_len].copy_from_slice(&label_data[..copy_len]);

        Self {
            magic: *FILE_MAGIC,
            version: FILE_VERSION,
            crypto_algorithm: algo as u8,
            flags: 0x01,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            original_file_size: file_size,
            wrapped_enc_key_len,
            wrapped_mac_key_len,
            key_label: label_bytes,
            iv_len,
            tag_len: 0,
            file_hmac: [0; 32],
            reserved: [0; 4],
            header_hmac: [0; 32],
        }
    }

    fn as_bytes_for_hmac(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const _ as *const u8,
                std::mem::size_of::<FileHeader>() - 32,
            )
        }
    }

    pub fn sign(&mut self, hmac_key: &[u8]) {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC key length is valid");
        mac.update(self.as_bytes_for_hmac());
        let result = mac.finalize();
        self.header_hmac.copy_from_slice(&result.into_bytes());
    }

    pub fn validate(&self, hmac_key: &[u8]) -> Result<()> {
        if &self.magic != FILE_MAGIC {
            return Err(anyhow!("Invalid file format or magic number"));
        }
        if self.version > FILE_VERSION {
            return Err(anyhow!(
                "Unsupported file version: {} (supports up to {})",
                self.version,
                FILE_VERSION
            ));
        }

        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC key length is valid");
        mac.update(self.as_bytes_for_hmac());
        mac.verify_slice(&self.header_hmac)
            .map_err(|_| anyhow!("Header HMAC verification failed. File may be corrupt or tampered with."))
    }

    pub fn get_crypto_algorithm(&self) -> Result<CryptoAlgorithm> {
        match self.crypto_algorithm {
            0 => Ok(CryptoAlgorithm::RsaAesCbc),
            1 => Ok(CryptoAlgorithm::RsaAesGcm),
            _ => Err(anyhow!(
                "Unknown crypto algorithm: {}",
                self.crypto_algorithm
            )),
        }
    }

    pub fn get_key_label(&self) -> String {
        let end = self.key_label.iter().position(|&b| b == 0).unwrap_or(32);
        String::from_utf8_lossy(&self.key_label[..end]).to_string()
    }

    pub fn uses_hardware_crypto(&self) -> bool {
        self.flags & 0x01 != 0
    }

    pub fn set_file_hmac(&mut self, hmac: &[u8]) {
        self.file_hmac.copy_from_slice(hmac);
    }

    pub fn get_file_hmac(&self) -> &[u8] {
        &self.file_hmac
    }
}

/// Overwrites the file with three passes of data (random, zeros, ones) before deleting.
/// This is a better-effort attempt at secure deletion but may not be sufficient
/// for all threat models, especially on modern SSDs with wear-leveling.
pub fn secure_delete_file(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)?;
    let file_size = metadata.len();
    if file_size == 0 {
        fs::remove_file(path)?;
        return Ok(());
    }

    let mut file = OpenOptions::new().write(true).open(path)?;

    // Pass 1: Ones
    file.seek(SeekFrom::Start(0))?;
    let one_buffer = vec![0xffu8; 64 * 1024];
    let mut written = 0u64;
    while written < file_size {
        let to_write = std::cmp::min(one_buffer.len() as u64, file_size - written) as usize;
        file.write_all(&one_buffer[..to_write])?;
        written += to_write as u64;
    }
    file.sync_all()?;

    // Pass 2: Zeros
    file.seek(SeekFrom::Start(0))?;
    let zero_buffer = vec![0u8; 64 * 1024];
    written = 0;
    while written < file_size {
        let to_write = std::cmp::min(zero_buffer.len() as u64, file_size - written) as usize;
        file.write_all(&zero_buffer[..to_write])?;
        written += to_write as u64;
    }
    file.sync_all()?;

    // Pass 3: Random data
    let mut buffer = vec![0u8; 64 * 1024];
    written = 0;
    while written < file_size {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut buffer);
        let to_write = std::cmp::min(buffer.len() as u64, file_size - written) as usize;
        file.write_all(&buffer[..to_write])?;
        written += to_write as u64;
    }
    file.sync_all()?;

    drop(file);
    fs::remove_file(path)?;
    Ok(())
} 
