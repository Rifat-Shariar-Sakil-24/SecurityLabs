# Encryption Script

This script provides functionality for AES and RSA encryption and decryption, RSA signature generation and verification, and SHA-256 hashing. The keys for AES and RSA are generated and stored in the `enc_keys` directory.

## Directory Structure

- `enc_keys/`
  - `key_aes.bin`: AES key file
  - `key_rsa.pem`: RSA private key file
  - `rsa_pub.pem`: RSA public key file
- `aes_encrypted.bin`: AES encrypted data file
- `rsa_encrypted.bin`: RSA encrypted data file
- `{filename}_rsa_signature.bin`: RSA signature file for the given filename

## Requirements

- Python 3.x
- pycryptodome library

Install the `pycryptodome` library using pip if you haven't already:

```bash
pip install pycryptodome
