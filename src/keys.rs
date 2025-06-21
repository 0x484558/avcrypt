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
use anyhow::{anyhow, Context, Result};
use cryptoki::{
    mechanism::Mechanism,
    object::{Attribute, KeyType, ObjectClass, ObjectHandle},
};
use std::time::Instant;

impl Pkcs11App {
    pub fn generate_rsa_key_pair(&self, label: &str, force: bool) -> Result<()> {
        if !force {
            if self
                .find_object(label, ObjectClass::PRIVATE_KEY, None)
                .is_ok()
            {
                return Err(anyhow!(
                    "An object with label '{}' already exists. Use --force to overwrite.",
                    label
                ));
            }
        }

        let mechanism = Mechanism::RsaPkcsKeyPairGen;
        let key_id = self.generate_random_bytes(16)?;
        let mod_size = 2048;

        let public_template = &[
            Attribute::Class(ObjectClass::PUBLIC_KEY.into()),
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(key_id.clone()),
            Attribute::KeyType(KeyType::RSA.into()),
            Attribute::ModulusBits(mod_size.into()),
            Attribute::Encrypt(true),
            Attribute::Wrap(true),
            Attribute::Modifiable(false),
        ];

        let private_template = &[
            Attribute::Class(ObjectClass::PRIVATE_KEY.into()),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(key_id.clone()),
            Attribute::KeyType(KeyType::RSA.into()),
            Attribute::Decrypt(true),
            Attribute::Unwrap(true),
            Attribute::Extractable(false),
            Attribute::Modifiable(false),
        ];

        println!("Generating RSA-{mod_size} key pair...");
        let start = Instant::now();
        let (public_key, private_key) = self
            .session
            .generate_key_pair(&mechanism, public_template, private_template)?;

        let elapsed = start.elapsed();
        println!(
            "✓ RSA-{mod_size} key pair generated successfully in {:.2}s",
            elapsed.as_secs_f64()
        );
        if self.verbose {
            println!("  Public key handle: {:#x}", public_key);
            println!("  Private key handle: {:#x}", private_key);
            println!("  Key ID: {}", hex::encode(&key_id));
        }
        Ok(())
    }

    pub fn generate_symmetric_key(
        &self,
        key_type: KeyType,
        size: usize,
    ) -> Result<ObjectHandle> {
        let mechanism = match key_type {
            KeyType::AES => Mechanism::AesKeyGen,
            KeyType::GENERIC_SECRET => Mechanism::GenericSecretKeyGen,
            _ => return Err(anyhow!("Unsupported key type for generation")),
        };

        let mut template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY.into()),
            Attribute::KeyType(key_type.into()),
            Attribute::Token(false),
            Attribute::ValueLen((size as u32).into()),
            Attribute::Extractable(true),
        ];

        match key_type {
            KeyType::AES => {
                template.push(Attribute::Encrypt(true));
                template.push(Attribute::Decrypt(true));
            }
            KeyType::GENERIC_SECRET => {
                template.push(Attribute::Sign(true));
                template.push(Attribute::Verify(true));
            }
            _ => {}
        }

        self.session
            .generate_key(&mechanism, &template)
            .context("Failed to generate symmetric key")
    }

    pub fn write_object_value(&self, label: &str, data: &[u8], force: bool) -> Result<()> {
        let token_info = self.pkcs11.as_ref().unwrap().get_token_info(self.slot)?;
        if let Some(free_memory) = token_info.free_public_memory() {
            if free_memory > 0 && data.len() > free_memory {
                return Err(anyhow!(
                    "Not enough public memory on token. Required: {} bytes, Available: {} bytes.",
                    data.len(),
                    free_memory
                ));
            }
        }

        if let Ok(existing_handle) = self.find_object(label, ObjectClass::DATA, None) {
            if force {
                if self.verbose {
                    println!(
                        "Data object with label '{}' already exists. Deleting it first.",
                        label
                    );
                }
                self.session.destroy_object(existing_handle)?;
            } else {
                return Err(anyhow!(
                    "Data object with label '{}' already exists. Use --force to overwrite.",
                    label
                ));
            }
        }

        if self.verbose {
            println!(
                "Creating new data object with label '{}' ({} bytes)",
                label,
                data.len()
            );
        }

        let template = &[
            Attribute::Class(ObjectClass::DATA.into()),
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Modifiable(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Application("avcrypt".as_bytes().to_vec()),
            Attribute::Value(data.to_vec()),
        ];

        let start = Instant::now();
        let handle = self
            .session
            .create_object(template)
            .context("Failed to create data object on token")?;
        let elapsed = start.elapsed();

        println!(
            "✓ Data object '{}' created successfully in {:.2}s",
            label,
            elapsed.as_secs_f64()
        );

        if self.verbose {
            println!("  Object handle: {:#x}", handle);
        }

        Ok(())
    }

    pub fn find_object(
        &self,
        label: &str,
        key_class: ObjectClass,
        key_type: Option<KeyType>,
    ) -> Result<ObjectHandle> {
        let mut template = vec![
            Attribute::Class(key_class.into()),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        if let Some(kt) = key_type {
            template.push(Attribute::KeyType(kt.into()));
        }
        let objects = self.session.find_objects(&template)?;
        objects
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Object '{}' not found", label))
    }
}
