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

use crate::TokenCapabilities;
use anyhow::{anyhow, Context, Result};
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    session::{Session, UserType},
    slot::Slot,
    types::AuthPin,
};
use std::env;

pub struct Pkcs11App {
    pub pkcs11: Option<Pkcs11>,
    pub session: Session,
    pub slot: Slot,
    pub capabilities: TokenCapabilities,
    pub verbose: bool,
}

impl Pkcs11App {
    pub fn new(pin: Option<&str>, slot_id: Option<u64>, verbose: bool) -> Result<Self> {
        let pkcs11_lib_path = env::var("PKCS11_LIB_PATH")
            .unwrap_or_else(|_| "Av338CryptokiD.dll".to_string());

        if verbose {
            println!("Using PKCS#11 library: {}", pkcs11_lib_path);
        }

        let pkcs11 = Pkcs11::new(&pkcs11_lib_path)?;

        pkcs11.initialize(CInitializeArgs::OsThreads)?;

        let slots = pkcs11.get_slots_with_token()?;
        let slot = if let Some(slot_id) = slot_id {
            slots
                .into_iter()
                .find(|s| s.id() == slot_id)
                .ok_or_else(|| anyhow!("Slot {} not found", slot_id))?
        } else {
            slots
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("No slots available. Is the token plugged in?"))?
        };

        let token_info = pkcs11.get_token_info(slot)?;
        if verbose {
            println!(
                "Using slot {}: {} - {}",
                slot.id(),
                token_info.label(),
                token_info.model()
            );
        }

        let session = pkcs11.open_rw_session(slot)?;

        if token_info.login_required() {
            if let Some(pin_str) = pin {
                session.login(UserType::User, Some(&AuthPin::new(pin_str.to_string())))?;
                if verbose {
                    println!("Successfully logged in.");
                }
            } else {
                return Err(anyhow!("PIN required for this token."));
            }
        }

        let capabilities = Pkcs11App::check_capabilities(&pkcs11, slot)?;

        Ok(Pkcs11App {
            pkcs11: Some(pkcs11),
            session,
            slot,
            capabilities,
            verbose,
        })
    }

    fn check_capabilities(
        pkcs11: &Pkcs11,
        slot: Slot,
    ) -> Result<TokenCapabilities> {
        let mechanisms = pkcs11.get_mechanism_list(slot)?;
        let token_info = pkcs11.get_token_info(slot)?;

        Ok(TokenCapabilities {
            has_rng: mechanisms.contains(&cryptoki::mechanism::MechanismType::GENERIC_SECRET_KEY_GEN),
            has_aes_keygen: mechanisms.contains(&cryptoki::mechanism::MechanismType::AES_KEY_GEN),
            has_aes_cbc: mechanisms.contains(&cryptoki::mechanism::MechanismType::AES_CBC),
            has_aes_cbc_pad: mechanisms.contains(&cryptoki::mechanism::MechanismType::AES_CBC_PAD),
            has_aes_gcm: mechanisms.contains(&cryptoki::mechanism::MechanismType::AES_GCM),
            has_sha256: mechanisms.contains(&cryptoki::mechanism::MechanismType::SHA256),
            has_sha512: mechanisms.contains(&cryptoki::mechanism::MechanismType::SHA512),
            has_hmac_sha256: mechanisms.contains(&cryptoki::mechanism::MechanismType::SHA256_HMAC),
            max_session_count: 0,
            total_memory: token_info.total_private_memory().unwrap_or(0) as u64,
            free_memory: token_info.free_private_memory().unwrap_or(0) as u64,
        })
    }

    pub fn generate_random_bytes(&self, num_bytes: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; num_bytes];
        self.session
            .generate_random_slice(&mut buffer)
            .context("Failed to generate random bytes")?;
        Ok(buffer)
    }
}

impl Drop for Pkcs11App {
    fn drop(&mut self) {
        if let Err(err) = self.session.logout() {
            eprintln!("Session logout error: {err}");
        }
        if let Some(pkcs11) = self.pkcs11.take() {
            pkcs11.finalize();
        }
    }
}
