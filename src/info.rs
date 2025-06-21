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
use crate::{
    constant_time_compare, FILE_MAGIC, FILE_VERSION,
};
use anyhow::{anyhow, Result};
use cryptoki::{
    mechanism::{Mechanism},
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    types::Ulong,
};
use std::time::Instant;

impl Pkcs11App {
    pub fn show_info(&self) -> Result<()> {
        let pkcs11 = self.pkcs11.as_ref().unwrap();
        let info = pkcs11.get_library_info()?;
        let token_info = pkcs11.get_token_info(self.slot)?;

        println!("--- PKCS#11 Info ---");
        println!(
            "Library: {} (ver {}.{})",
            info.library_description(),
            info.library_version().major(),
            info.library_version().minor()
        );
        println!(
            "Cryptoki Version: {}.{}",
            info.cryptoki_version().major(),
            info.cryptoki_version().minor()
        );
        println!("--- Token Info ---");
        println!("Slot: {}", self.slot.id());
        println!("Label: {}", token_info.label());
        println!("Manufacturer: {}", token_info.manufacturer_id());
        println!("Model: {}", token_info.model());
        println!("Serial: {}", token_info.serial_number());
        println!("Hardware version: {}.{}", 
            token_info.hardware_version().major(),
            token_info.hardware_version().minor()
        );
        println!("PIN initialized: {}", token_info.user_pin_initialized());
        println!("--- Memory ---");
        println!("Total Public: {} bytes", token_info.total_public_memory().map_or("N/A".to_string(), |v| v.to_string()));
        println!("Free Public: {} bytes", token_info.free_public_memory().map_or("N/A".to_string(), |v| v.to_string()));
        println!("Total Private: {} bytes", token_info.total_private_memory().map_or("N/A".to_string(), |v| v.to_string()));
        println!("Free Private: {} bytes", token_info.free_private_memory().map_or("N/A".to_string(), |v| v.to_string()));
        println!("--- Capabilities ---");
        println!("RNG: {}", self.capabilities.has_rng);
        println!("AES Keygen: {}", self.capabilities.has_aes_keygen);
        println!("AES-CBC: {}", self.capabilities.has_aes_cbc);
        println!("AES-GCM: {}", self.capabilities.has_aes_gcm);
        println!("SHA-256: {}", self.capabilities.has_sha256);
        println!("SHA-512: {}", self.capabilities.has_sha512);
        Ok(())
    }

    pub fn list_objects(&self, detailed: bool) -> Result<()> {
        let classes = [
            ObjectClass::PUBLIC_KEY,
            ObjectClass::PRIVATE_KEY,
            ObjectClass::SECRET_KEY,
            ObjectClass::CERTIFICATE,
            ObjectClass::DATA,
        ];
        let mut count = 0;
        println!("--- Stored Objects ---");
        for &class in &classes {
            let template = vec![Attribute::Class(class.into())];
            match self.session.find_objects(&template) {
                Ok(objects) => {
                    for object_handle in objects {
                        count += 1;
                        self.print_object_info(object_handle, detailed)?;
                    }
                }
                Err(e) => {
                    if self.verbose {
                        eprintln!(
                            "Could not search for {:?}: {}. This may be normal.",
                            class, e
                        );
                    }
                }
            }
        }
        if count == 0 {
            println!("No objects found on token.");
        }
        Ok(())
    }

    fn print_object_info(&self, object_handle: ObjectHandle, detailed: bool) -> Result<()> {
        let attrs_to_get = vec![
            AttributeType::Class,
            AttributeType::Label,
            AttributeType::KeyType,
            AttributeType::Id,
        ];

        let attributes = self.session.get_attributes(object_handle, &attrs_to_get)?;

        let class = if let Some(attr) = attributes.get(0) {
            match attr {
                Attribute::Class(c) => *c,
                _ => ObjectClass::DATA,
            }
        } else {
            ObjectClass::DATA
        };

        let label = if let Some(attr) = attributes.get(1) {
            match attr {
                Attribute::Label(bytes) => String::from_utf8_lossy(bytes).to_string(),
                _ => "<no label>".to_string(),
            }
        } else {
            "<no label>".to_string()
        };

        let key_type = if let Some(attr) = attributes.get(2) {
            match attr {
                Attribute::KeyType(kt) => Some(*kt),
                _ => None,
            }
        } else {
            None
        };

        let key_id = if let Some(attr) = attributes.get(3) {
            match attr {
                Attribute::Id(bytes) => Some(bytes.clone()),
                _ => None,
            }
        } else {
            None
        };

        let mut modulus_info: Option<Ulong> = None;
        if detailed {
            if let Some(Attribute::KeyType(KeyType::RSA)) = attributes.get(2) {
                if let Ok(extra_attrs) = self.session.get_attributes(object_handle, &[AttributeType::ModulusBits]) {
                    if let Some(Attribute::ModulusBits(bits)) = extra_attrs.get(0) {
                        modulus_info = Some((*bits).into());
                    }
                }
            }
        }

        print!(
            "Handle: {:#010x} | Class: {:<12} | Label: {:<20}",
            object_handle,
            format!("{:?}", class),
            label
        );

        if detailed {
            if let Some(kt) = key_type {
                print!(" | Type: {:<12}", format!("{:?}", kt));
            }
            if let Some(id) = key_id {
                print!(" | ID: {}", hex::encode(id));
            }
            if let Some(bits) = modulus_info {
                print!(" | Modulus: {} bits", bits);
            }
        }
        println!();
        Ok(())
    }

    pub fn read_object_value(&self, label: &str, class_str: &str) -> Result<()> {
        let object_class = match class_str.to_lowercase().as_str() {
            "publickey" | "public" => ObjectClass::PUBLIC_KEY,
            "privatekey" | "private" => ObjectClass::PRIVATE_KEY,
            "secretkey" | "secret" => ObjectClass::SECRET_KEY,
            "certificate" => ObjectClass::CERTIFICATE,
            "data" => ObjectClass::DATA,
            _ => return Err(anyhow!("Invalid object class: {}", class_str)),
        };

        println!("Searching for {:?} object with label '{}'...", object_class, label);

        let object_handle = self.find_object(label, object_class, None)?;

        let attributes = self.session.get_attributes(object_handle, &[AttributeType::Value])
            .map_err(|e| anyhow!("Failed to get object attributes: {}. This can happen if you try to read a sensitive key.", e))?;

        if let Some(Attribute::Value(value)) = attributes.get(0) {
            if value.is_empty() {
                println!("  Value attribute is present but empty.");
            } else {
                println!("  Value ({} bytes):", value.len());
                println!("    Hex: {}", hex::encode(&value));

                let is_printable = value.iter().all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace());
                if is_printable {
                    println!("    ASCII: {}", String::from_utf8_lossy(&value));
                }
            }
        } else {
            println!("  No CKA_VALUE attribute found for this object.");
            println!("  Note: This is normal for objects without a value attribute.");
        }

        Ok(())
    }

    pub fn self_test(&self) -> Result<()> {
        println!("--- Running Self-Tests ---");
        let start_time = Instant::now();
        let mut failed_tests = 0;
        let mut passed_tests = 0;
        let sha_test_data = b"The quick brown fox jumps over the lazy dog";
        let crypto_test_data = b"The quick brown fox jumps over the lazy dog".repeat(1024 * 10);

        println!("Testing RNG...");
        match self.generate_random_bytes(32) {
            Ok(bytes) => {
                println!("  ✓ RNG returned {} bytes", bytes.len());
                passed_tests += 1;
            }
            Err(e) => {
                println!("  ✗ RNG failed: {}", e);
                failed_tests += 1;
            }
        };

        println!("Testing SHA-256...");
        match self.session.digest(&Mechanism::Sha256, sha_test_data) {
            Ok(hash) => {
                let expected_hash_hex =
                    "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
                let expected_hash = hex::decode(expected_hash_hex)?;
                if constant_time_compare(&hash, &expected_hash) {
                    println!("  ✓ SHA-256 hash matches expected value.");
                    passed_tests += 1;
                } else {
                    println!("  ✗ SHA-256 hash mismatch!");
                    if self.verbose {
                        println!("    Got:      {}", hex::encode(&hash));
                        println!("    Expected: {}", expected_hash_hex);
                    }
                    failed_tests += 1;
                }
            }
            Err(e) => {
                println!("  ✗ SHA-256 failed: {}", e);
                failed_tests += 1;
            }
        };

        println!("Testing AES-256-CBC encryption...");
        if self.capabilities.has_aes_cbc_pad {
            match self.test_cbc_encryption(&crypto_test_data) {
                Ok(()) => {
                    println!("  ✓ AES-256-CBC encrypt/decrypt successful.");
                    passed_tests += 1;
                }
                Err(e) => {
                    println!("  ✗ AES-256-CBC failed: {}", e);
                    failed_tests += 1;
                }
            }
        } else {
            println!("  ! AES-256-CBC pad not supported, skipping test.");
        }

        println!("Testing file format constants...");
        if FILE_MAGIC == b"avcrypt\0" && FILE_VERSION == 1 {
            println!("  ✓ File format constants are correct.");
            passed_tests += 1;
        } else {
            println!("  ✗ File format constants are incorrect!");
            failed_tests += 1;
        }

        println!("--- Test Summary ---");
        println!(
            "Result: {} passed, {} failed in {:.2}s",
            passed_tests,
            failed_tests,
            start_time.elapsed().as_secs_f64()
        );
        if failed_tests > 0 {
            Err(anyhow!("{} self-tests failed.", failed_tests))
        } else {
            Ok(())
        }
    }

    fn test_cbc_encryption(&self, test_data: &[u8]) -> Result<()> {
        let key = self.generate_symmetric_key(KeyType::AES, 32)?;
        let iv = self.generate_random_bytes(16)?;
        let mut iv_bytes = [0u8; 16];
        iv_bytes.copy_from_slice(&iv);

        let mechanism = Mechanism::AesCbcPad(iv_bytes);

        let encrypted_data = self.session.encrypt(&mechanism, key, test_data)?;
        let decrypted_data = self.session.decrypt(&mechanism, key, &encrypted_data)?;

        if !constant_time_compare(test_data, &decrypted_data) {
            return Err(anyhow!("Decrypted CBC data does not match original data"));
        }

        self.session.destroy_object(key)?;
        Ok(())
    }
}
