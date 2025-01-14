from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import constant_time
import os
import base64
import getpass


def derive_key_from_password(password, salt, length=32):
    """Derive a cryptographic key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_key_file(key, password):
    """Encrypt the AES key and save it to a file."""
    salt = os.urandom(16)
    derived_key = derive_key_from_password(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
    encrypter = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_key = padder.update(key) + padder.finalize()
    encrypted_key = encrypter.update(padded_key) + encrypter.finalize()

    with open('aes_key.key', 'wb') as key_file:
        key_file.write(salt + iv + encrypted_key)
    print("AES key saved and encrypted to 'aes_key.key'.")


def decrypt_key_file(password):
    """Decrypt the AES key from the file using the provided password."""
    with open('aes_key.key', 'rb') as key_file:
        data = key_file.read()

    salt = data[:16]
    iv = data[16:32]
    encrypted_key = data[32:]

    derived_key = derive_key_from_password(password, salt)
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        padded_key = decryptor.update(encrypted_key) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        key = unpadder.update(padded_key) + unpadder.finalize()

        print("AES key successfully decrypted.")
        return key
    except Exception as e:
        print(f"Failed to decrypt AES key: {e}")
        return None


def generate_key():
    """Generate a random 256-bit AES key."""
    return os.urandom(32)


def encrypt_file(file_name, key):
    """Encrypt a file using AES (CBC mode) and save the encrypted file."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encrypter = cipher.encryptor()

    with open(file_name, 'rb') as file:
        file_data = file.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_data) + padder.finalize()
    encrypted_data = encrypter.update(padded_data) + encrypter.finalize()

    encrypted_file_name = file_name + '.enc'
    with open(encrypted_file_name, 'wb') as file:
        file.write(iv + encrypted_data)

    print(f'File "{file_name}" encrypted to "{encrypted_file_name}".')


def decrypt_file_with_input_key(encrypted_file_name, key):
    """Decrypt a file using the provided AES key."""
    with open(encrypted_file_name, 'rb') as file:
        file_data = file.read()

    iv = file_data[:16]
    encrypted_data = file_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

        decrypted_file_name = encrypted_file_name.replace('.enc', '.dec')
        with open(decrypted_file_name, 'wb') as file:
            file.write(decrypted_data)

        print(f'File "{encrypted_file_name}" decrypted to "{decrypted_file_name}".')
    except Exception as e:
        print(f"Decryption failed: {e}")


if __name__ == '__main__':
    file_name = '/home/abbish.basit@vaival.tech/Desktop/AES/encrypted.txt'

    # Generate and encrypt the key
    key = generate_key()
    password = getpass.getpass("Set a password to protect the AES key: ")
    encrypt_key_file(key, password)

    # Encrypt the file
    encrypt_file(file_name, key)

    # Decrypt the key
    password = getpass.getpass("Enter the password to decrypt the AES key: ")
    key = decrypt_key_file(password)
    if key:
        # Decrypt the file
        encrypted_file = file_name + '.enc'
        decrypt_file_with_input_key(encrypted_file, key)
