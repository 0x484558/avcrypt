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

use anyhow::{anyhow, Context, Result};
use avcrypt::app::Pkcs11App;
use avcrypt::files::secure_delete_file;
use avcrypt::SecurePin;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "avcrypt")]
#[command(about = "Secure file encryption using Avtor SecureToken-338S, PKCS#11 HSM (Infineon SLE 78CUFX3000PH, M7893 security controller)", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(short, long, env = "PKCS11_PIN")]
    pin: Option<String>,
    #[arg(short, long)]
    verbose: bool,
    #[arg(short, long)]
    slot: Option<u64>,
}

#[derive(Subcommand)]
enum Commands {
    Init {
        #[arg(short, long, default_value = "avcrypt")]
        label: String,
        #[arg(short, long)]
        force: bool,
    },
    Encrypt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(short, long, default_value = "avcrypt")]
        key_label: String,
        #[arg(short = 'd', long)]
        delete_original: bool,
    },
    Decrypt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(short, long)]
        key_label: Option<String>,
        #[arg(short = 'd', long)]
        delete_encrypted: bool,
    },
    ListObjects {
        #[arg(short, long)]
        detailed: bool,
    },
    WriteObject {
        #[arg(short, long, help = "The label for the data object")]
        label: String,
        #[arg(short, long, help = "Path to the file containing data", conflicts_with("data"))]
        file: Option<PathBuf>,
        #[arg(long, help = "Raw string data", conflicts_with("file"))]
        data: Option<String>,
        #[arg(short, long)]
        force: bool,
    },
    ReadObject {
        #[arg(short, long, help = "The label of the object to read")]
        label: String,
        #[arg(short, long, help = "The class of the object (PublicKey, PrivateKey, SecretKey, Certificate, Data)", default_value = "Data")]
        class: String,
    },
    SelfTest,
    Info,
    License,
}

fn get_pin(pin_arg: Option<String>, needs_pin: bool) -> Result<Option<SecurePin>> {
    match pin_arg {
        None if needs_pin => {
            Ok(Some(SecurePin { pin: rpassword::prompt_password("Enter PIN: ").context("Failed to read PIN")? }))
        }
        Some(pin) => Ok(Some(SecurePin { pin })),
        None => Ok(None),
    }
}

fn show_license() {
    println!("avcrypt - Secure file encryption using Avtor SecureToken-338S");
    println!("Copyright (C) 2024 Hex <hex@aleph0.ai>");
    println!();
    println!("Licensed under the European Union Public Licence (EUPL) v1.2");
    println!();
    println!("This software is distributed under the terms of the European Union");
    println!("Public Licence (EUPL) v1.2. You may obtain a copy of the licence at:");
    println!("https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12");
    println!();
    println!("This software is provided \"as is\" without warranties of any kind.");
    println!("See LICENSE.txt for the complete license terms.");
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if matches!(cli.command, Commands::License) {
        show_license();
        return Ok(());
    }

    if cli.verbose {
        println!("avcrypt v{} - Licensed under EUPL v1.2", env!("CARGO_PKG_VERSION"));
        println!("Copyright (C) 2024 Hex <hex@aleph0.ai>");
        println!();
    }

    let pin = get_pin(cli.pin, true)?;
    let app = Pkcs11App::new(pin.as_ref().map(|p| p.pin.as_str()), cli.slot, cli.verbose)?;

    match cli.command {
        Commands::Init {
            label,
            force,
        } => app.generate_rsa_key_pair(&label, force)?,
        Commands::Encrypt {
            input,
            output,
            key_label,
            delete_original,
        } => {
            let output_path = output.unwrap_or_else(|| {
                let mut os_string = input.as_os_str().to_owned();
                os_string.push(".enc");
                PathBuf::from(os_string)
            });
            if input.extension().map_or(false, |ext| ext == "enc") {
                return Err(anyhow!(
                    "File appears to be already encrypted (.enc extension)"
                ));
            }
            app.encrypt_file(&input, &output_path, &key_label)?;
            if delete_original {
                secure_delete_file(&input)?;
                println!("✓ Original file securely deleted");
            }
        }
        Commands::Decrypt {
            input,
            output,
            key_label,
            delete_encrypted,
        } => {
            if !input.extension().map_or(false, |ext| ext == "enc") {
                eprintln!("Warning: Input file does not have .enc extension, treating as raw data.");
            }
            let output_path = output.unwrap_or_else(|| {
                let p = Path::new(&input);
                if p.extension().map_or(false, |s| s == "enc") {
                    p.with_extension("")
                } else {
                    let mut os_string = p.as_os_str().to_owned();
                    os_string.push(".decrypted");
                    PathBuf::from(os_string)
                }
            });
            app.decrypt_file(&input, &output_path, key_label.as_deref())?;
            if delete_encrypted {
                secure_delete_file(&input)?;
                println!("✓ Encrypted file deleted");
            }
        }
        Commands::ListObjects { detailed } => {
            app.list_objects(detailed)?;
        }
        Commands::WriteObject {
            label,
            file,
            data,
            force,
        } => {
            let object_data = if let Some(path) = file {
                fs::read(path)?
            } else if let Some(string_data) = data {
                string_data.into_bytes()
            } else {
                return Err(anyhow!(
                    "Either --file or --data must be provided to write an object"
                ));
            };
            app.write_object_value(&label, &object_data, force)?;
        }
        Commands::ReadObject { label, class } => {
            app.read_object_value(&label, &class)?;
        }
        Commands::SelfTest => {
            app.self_test()?;
        }
        Commands::Info => {
            app.show_info()?;
        }
        Commands::License => unreachable!(),
    }
    Ok(())
}
