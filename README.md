# File-Encryption-using-AES-python
**Required Libraries**
cryptography: For encryption, decryption, and key derivation.
os: For random value generation and file handling.
base64: For encoding and decoding keys.
getpass: For secure password input.

**Script Functionality**
Encrypt and decrypt files using AES (CBC mode).
Securely protect the AES encryption key with a password.
Derive cryptographic keys from passwords using PBKDF2.

**Functions**
derive_key_from_password: Derives a secure key from a user-provided password and salt.
encrypt_key_file: Encrypts the AES key and saves it in a protected .key file.
decrypt_key_file: Decrypts the AES key from the .key file using the password.
generate_key: Creates a random 256-bit AES key.
encrypt_file: Encrypts a file and saves it with a .enc extension.
decrypt_file_with_input_key: Decrypts an encrypted file and saves it with a .dec extension.

**Execution Flow**
Generate an AES key and protect it with a password.
Encrypt a file using the generated AES key.
Decrypt the AES key using the password.
Use the decrypted AES key to decrypt the file.
This script ensures secure encryption with password-protected key storage.
