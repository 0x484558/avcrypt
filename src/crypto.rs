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

use crate::app::Pkcs11App;
use crate::files::FileHeader;
use crate::{CryptoAlgorithm, AES_KEY_SIZE, AES_BLOCK_SIZE, CHUNK_SIZE, SHA256_SIZE};
use anyhow::{anyhow, Context, Result};
use cryptoki::{
    mechanism::{Mechanism},
    object::{Attribute, AttributeType, KeyType, ObjectClass},
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;

impl Pkcs11App {
    pub fn encrypt_file(
        &self,
        input_path: &Path,
        output_path: &Path,
        key_label: &str,
    ) -> Result<()> {
        if !self.capabilities.has_aes_cbc_pad || !self.capabilities.has_hmac_sha256 {
            return Err(anyhow!("Token does not support required mechanisms (AES-CBC-PAD and HMAC-SHA256) for encryption."));
        }

        let start = Instant::now();
        let mut input_file = File::open(input_path)?;
        let original_file_size = input_file.metadata()?.len();

        if self.verbose {
            println!("Encrypting '{}' -> '{}' using AES-CBC+HMAC", input_path.display(), output_path.display());
        }

        let priv_template = &[
            Attribute::Class(ObjectClass::PRIVATE_KEY.into()),
            Attribute::Label(key_label.as_bytes().to_vec()),
            Attribute::KeyType(KeyType::RSA.into()),
        ];

        let private_keys = self.session.find_objects(priv_template)?;
        if private_keys.is_empty() {
            return Err(anyhow!("No private RSA key with label '{}' found", key_label));
        }

        let priv_handle = private_keys[0];
        let attrs = self.session.get_attributes(priv_handle, &[AttributeType::Id])?;
        let key_id = if let Some(Attribute::Id(id)) = attrs.get(0) {
            id.clone()
        } else {
            Vec::new()
        };

        let wrapping_key = if !key_id.is_empty() {
            let pub_template = &[
                Attribute::Class(ObjectClass::PUBLIC_KEY.into()),
                Attribute::Id(key_id.clone()),
                Attribute::KeyType(KeyType::RSA.into()),
            ];
            match self.session.find_objects(pub_template)?.into_iter().next() {
                Some(h) => h,
                None => {
                    self.find_object(key_label, ObjectClass::PUBLIC_KEY, Some(KeyType::RSA))?
                }
            }
        } else {
            self.find_object(key_label, ObjectClass::PUBLIC_KEY, Some(KeyType::RSA))?
        };

        if self.verbose {
            println!("Wrapping with public key handle: {:#x}", wrapping_key);
        }

        let enc_key = self.generate_symmetric_key(KeyType::AES, AES_KEY_SIZE)?;
        let mac_key = self.generate_symmetric_key(KeyType::GENERIC_SECRET, SHA256_SIZE)?;

        let wrapped_enc_key = self.session.wrap_key(&Mechanism::RsaPkcs, wrapping_key, enc_key)?;
        let wrapped_mac_key = self.session.wrap_key(&Mechanism::RsaPkcs, wrapping_key, mac_key)?;

        let iv = self.generate_random_bytes(AES_BLOCK_SIZE)?;
        let mut iv_bytes = [0u8; AES_BLOCK_SIZE];
        iv_bytes.copy_from_slice(&iv);

        let mut header = FileHeader::new(
            original_file_size,
            wrapped_enc_key.len() as u16,
            wrapped_mac_key.len() as u16,
            key_label,
            iv.len() as u8,
            CryptoAlgorithm::RsaAesCbc,
        );

        let mut output_file = OpenOptions::new().write(true).create(true).truncate(true).open(output_path)?;
        let header_size = std::mem::size_of::<FileHeader>();
        output_file.seek(SeekFrom::Start(header_size as u64))?;
        output_file.write_all(&wrapped_enc_key)?;
        output_file.write_all(&wrapped_mac_key)?;
        output_file.write_all(&iv)?;

        let mechanism = Mechanism::AesCbcPad(iv_bytes);
        self.session.encrypt_init(&mechanism, enc_key)?;
        self.session.sign_init(&Mechanism::Sha256Hmac, mac_key)?;

        let mut buffer = vec![0; CHUNK_SIZE];
        loop {
            let bytes_read = input_file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            let encrypted_chunk = self.session.encrypt_update(&buffer[..bytes_read])?;
            self.session.sign_update(&encrypted_chunk)?;
            output_file.write_all(&encrypted_chunk)?;
        }
        let final_chunk = self.session.encrypt_final()?;
        self.session.sign_update(&final_chunk)?;
        output_file.write_all(&final_chunk)?;

        let hmac = self.session.sign_final()?;
        header.set_file_hmac(&hmac);

        output_file.seek(SeekFrom::Start(0))?;
        let header_bytes: [u8; std::mem::size_of::<FileHeader>()] = unsafe { std::mem::transmute(header) };
        output_file.write_all(&header_bytes)?;

        self.session.destroy_object(enc_key)?;
        self.session.destroy_object(mac_key)?;

        println!("✓ Encryption successful in {:.2}s", start.elapsed().as_secs_f64());
        Ok(())
    }

    pub fn decrypt_file(
        &self,
        input_path: &Path,
        output_path: &Path,
        key_label: Option<&str>,
    ) -> Result<()> {
        let start = Instant::now();
        let mut input_file = File::open(input_path)?;

        let mut header_bytes = [0u8; std::mem::size_of::<FileHeader>()];
        input_file.read_exact(&mut header_bytes)?;
        let header: FileHeader = unsafe { std::mem::transmute(header_bytes) };

        let key_label_from_header = header.get_key_label();
        let final_key_label = key_label.unwrap_or(&key_label_from_header);

        let mut wrapped_enc_key = vec![0; header.wrapped_enc_key_len as usize];
        input_file.read_exact(&mut wrapped_enc_key)?;
        let mut wrapped_mac_key = vec![0; header.wrapped_mac_key_len as usize];
        input_file.read_exact(&mut wrapped_mac_key)?;
        let mut iv = vec![0; header.iv_len as usize];
        input_file.read_exact(&mut iv)?;
        let mut iv_bytes = [0u8; AES_BLOCK_SIZE];
        iv_bytes.copy_from_slice(&iv);

        let search_template = [
            Attribute::Class(ObjectClass::PRIVATE_KEY.into()),
            Attribute::Label(final_key_label.as_bytes().to_vec()),
        ];
        let candidate_keys = self.session.find_objects(&search_template)?;
        if candidate_keys.is_empty() {
            return Err(anyhow!("No private key with label '{}' found", final_key_label));
        }

        if self.verbose {
            println!("Wrapped enc key length: {} bytes", wrapped_enc_key.len());
            for &handle in &candidate_keys {
                match self.session.get_attributes(handle, &[AttributeType::ModulusBits]) {
                    Ok(attr_vals) => {
                        if let Some(Attribute::ModulusBits(bits)) = attr_vals.get(0) {
                            println!("  Candidate key {:#x}: modulus {} bits", handle, bits);
                        } else {
                            println!("  Candidate key {:#x}: modulus unknown", handle);
                        }
                    }
                    Err(_e) => {
                        println!("  Candidate key {:#x}: unable to read modulus bits", handle);
                    }
                }
            }
        }

        let enc_key_template = &[
            Attribute::Class(ObjectClass::SECRET_KEY.into()),
            Attribute::KeyType(KeyType::AES.into()),
            Attribute::ValueLen((AES_KEY_SIZE as u32).into()),
            Attribute::Decrypt(true),
            Attribute::Encrypt(true),
            Attribute::Extractable(false),
        ];

        let mac_key_template = &[
            Attribute::Class(ObjectClass::SECRET_KEY.into()),
            Attribute::KeyType(KeyType::GENERIC_SECRET.into()),
            Attribute::ValueLen((SHA256_SIZE as u32).into()),
            Attribute::Sign(true),
            Attribute::Verify(true),
            Attribute::Extractable(false),
        ];

        let mut unwrap_success = None;
        let mut last_error = None;
        for &priv_handle in &candidate_keys {
            if self.verbose {
                let attrs = self.session.get_attributes(priv_handle, &[AttributeType::ModulusBits]);
                match attrs {
                    Ok(attr_vals) => {
                        if let Some(Attribute::ModulusBits(bits)) = attr_vals.get(0) {
                            println!("Trying private key handle {:#x} ({} bits) for unwrapping...", priv_handle, bits);
                        } else {
                            println!("Trying private key handle {:#x} (modulus unknown) for unwrapping...", priv_handle);
                        }
                    }
                    Err(_e) => {
                        println!("Trying private key handle {:#x} for unwrapping...", priv_handle);
                    }
                }
            }
            match self.session.unwrap_key(&Mechanism::RsaPkcs, priv_handle, &wrapped_enc_key, enc_key_template) {
                Ok(enc_key) => {
                    match self.session.unwrap_key(&Mechanism::RsaPkcs, priv_handle, &wrapped_mac_key, mac_key_template) {
                        Ok(mac_key) => {
                            unwrap_success = Some((enc_key, mac_key));
                            break;
                        }
                        Err(_e) => {
                            let _ = self.session.destroy_object(enc_key);
                            last_error = Some(_e);
                            continue;
                        }
                    }
                }
                Err(_e) => {
                    last_error = Some(_e);
                    continue;
                }
            }
        }

        let (enc_key, mac_key) = match unwrap_success {
            Some(pair) => pair,
            None => {
                if let Some(e) = last_error {
                    return Err(anyhow!("Failed to unwrap keys: {}", e));
                } else {
                    return Err(anyhow!("Failed to unwrap keys with any matching private key"));
                }
            }
        };

        self.session.verify_init(&Mechanism::Sha256Hmac, mac_key)?;
        let mechanism = Mechanism::AesCbcPad(iv_bytes);
        self.session.decrypt_init(&mechanism, enc_key)?;

        let mut output_file = OpenOptions::new().write(true).create(true).truncate(true).open(output_path)?;
        let mut buffer = vec![0; CHUNK_SIZE];
        loop {
            let bytes_read = input_file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            let ciphertext_chunk = &buffer[..bytes_read];
            self.session.verify_update(ciphertext_chunk)?;
            let plaintext_chunk = self.session.decrypt_update(ciphertext_chunk)?;
            output_file.write_all(&plaintext_chunk)?;
        }

        let final_plaintext = self.session.decrypt_final().context("Decryption failed. File may be corrupt.")?;
        output_file.write_all(&final_plaintext)?;

        self.session.verify_final(header.get_file_hmac())
            .context("HMAC verification failed. File is corrupt or has been tampered with.")?;

        self.session.destroy_object(enc_key)?;
        self.session.destroy_object(mac_key)?;

        if self.verbose {
            println!("Private keys found with label '{}': {}", final_key_label, candidate_keys.len());
            for &handle in &candidate_keys {
                match self.session.get_attributes(handle, &[AttributeType::ModulusBits]) {
                    Ok(attr_vals) => {
                        if let Some(Attribute::ModulusBits(bits)) = attr_vals.get(0) {
                            println!("  Handle {:#x}: modulus {} bits", handle, bits);
                        } else {
                            println!("  Handle {:#x}: modulus (unknown)", handle);
                        }
                    }
                    Err(_e) => {
                        println!("  Handle {:#x}: modulus (unknown, error reading)", handle);
                    }
                }
            }
        }

        println!("✓ Decryption and integrity check successful in {:.2}s", start.elapsed().as_secs_f64());
        Ok(())
    }
}
