from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
import secrets


def encrypt_data(data, key, initialization_vector):
    cipher = Cipher(algorithms.AES(key), modes.CFB(initialization_vector), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return ciphertext


def decrypt_data(ciphertext, key, initialization_vector):
    cipher = Cipher(algorithms.AES(key), modes.CFB(initialization_vector), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data.decode()


def generate_key():
    """
    Generate a random 32-byte key for encryption.
    """
    key = secrets.token_bytes(32)
    return key


def generate_initialization_vector():
    """
    Generate a random 16-byte initialization vector for encryption.
    """
    iv = secrets.token_bytes(16)
    return iv


