# avcrypt

avcrypt is a command-line tool for secure file encryption and decryption using hardware security modules (HSMs) via the PKCS#11 interface.

Developed in the course of reverse-engineering efforts and experimentation with the Avtor SecureToken-338S device (Infineon SLE 78CUFX3000PH, M7893 security controller).

### A Note on Ukrainian Cryptography Standards (DSTU)

An intriguing aspect of the Avtor SecureToken-338S is its handling of Ukrainian national cryptographic standards, specifically DSTU 4145 for elliptic curve digital signatures. My deep analysis confirms the token's capability to generate and store valid DSTU 4145 key pairs. The `CKA_EC_PARAMS` attribute on these keys contains the correct, DER-encoded object identifiers (OIDs) for the standardized DSTU curves, and the keys are appropriately flagged for signing operations (`CKA_SIGN=CK_TRUE`).

However, the implementation presents a formidable challenge to integration with standard cryptographic middleware. Despite the presence of valid keys, the token **fails to expose any functional DSTU signing mechanism** through the standardized PKCS#11 interface. Brute-forcing discovery across the vendor-defined mechanism space (`CKM_VENDOR_DEFINED`) consistently results in `CKR_MECHANISM_INVALID`, indicating that no such standard-compliant entry point exists.

This leads to the ineluctable conclusion that Avtor has eschewed the robust, interoperable, and internationally recognized PKCS#11 mechanism framework. Instead, they have opted for a proprietary, non-standard interface, through PC/SC communications with the so-called "УкрКОС" (Ukrainian Cryptographic Operating System) - which is not an advantage, but a significant technical deficiency, offering negligible benefits while severely hindering the token's utility. By creating a siloed ecosystem, it obstructs seamless integration with established security software, necessitating custom, vendor-specific solutions for what ought to be a standardized operation, revealing a curious case of corruption covered by technological sophistication.

### Prerequisites

- Rust toolchain (1.70 or later)
- PKCS#11 library for your HSM (e.g., `Av338CryptokiD.dll` for Avtor devices)
- Any PKCS#11 v2.40+ compliant HSM with:
  - RSA key generation (2048-bit minimum)
  - AES key generation
  - AES-CBC-PAD encryption
  - SHA256-HMAC
  - Key wrapping/unwrapping

### Building

```bash
git clone <repository-url>
cd avcrypt
cargo build --release
```

## Usage

### Environment Variables

- `PKCS11_LIB_PATH`: Path to PKCS#11 library (default: `Av338CryptokiD.dll`)
- `PKCS11_PIN`: HSM user PIN (can also be provided via `--pin` or interactive prompt)

### Commands

#### Initialize HSM with a new key pair labeled `avcrypt`
```bash
avcrypt init
```

#### File encryption/decryption
```bash
avcrypt encrypt --input document.pdf
# Creates document.pdf.enc
avcrypt decrypt --input document.pdf.enc
# Creates document.pdf
```

#### Object storage
```bash
avcrypt list-objects --detailed
avcrypt write-object --label config --file config.json
avcrypt read-object --label config
```

#### Other commands
```bash
# Run crypto self-test
avcrypt self-test
# Show token information
avcrypt info
# Show license information
avcrypt license
```

See `avcrypt --help` for more information.

## File Format

avcrypt uses a custom binary format with the following structure:

```
[Header (152 bytes)]
[Wrapped AES Key (256 bytes for RSA-2048)]
[Wrapped HMAC Key (256 bytes for RSA-2048)]
[IV (16 bytes)]
[Encrypted Data (variable)]
```

The header contains:
- Magic bytes: `avcrypt\0`
- Version: 1
- Algorithm: RSA+AES-CBC
- Timestamps and metadata
- Key label and lengths
- File HMAC for integrity

## Error Handling

Common issues and solutions:

- **"No slots available"**: Check HSM connection and drivers
- **"PIN required"**: Set `PKCS11_PIN` environment variable or use `--pin`
- **"Key not found"**: Use `list-objects` to verify key labels
- **"Unwrap failed"**: Ensure correct key pair is used for decryption

## Copyright and License

Copyright © 2025 Vladyslav "Hex" Yamkovyi <<hex@aleph0.ai>>

Licensed under the European Union Public Licence (EUPL) v1.2.
See [LICENSE.txt](LICENSE.txt) for the full license text.

Any derivative works must be licensed under EUPL v1.2 or a compatible license.

## Disclaimer

This software is provided "as is" without warranties of any kind. The cryptographic implementation has not undergone formal security audit. Use at your own risk in production environments.
