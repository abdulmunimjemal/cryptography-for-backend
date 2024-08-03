from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os


# Using Strategy Pattern
class EncryptionStrategy:
    def encrypt(self, key, data):
        raise NotImplementedError
    def decrypt(self, key, data):
        raise NotImplementedError

class AESEncryption(EncryptionStrategy):
    def encrypt(self, key, data):
        iv = os.urandom(16) # random strings in byte
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        return iv + encrypted_data
    
    def decrypt(self, key, data):
        iv = data[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(data[16:]) + decryptor.finalize()
        return decrypted_data

class EncryptionContext:
    def __init__(self, strategy: EncryptionStrategy):
        self.strategy = strategy
    
    def encrypt(self, key, data):
        return self.strategy.encrypt(key, data)
    
    def decrypt(self, key, data):
        return self.strategy.decrypt(key, data)
    
# Generate a key from a password
class KeyDerivation:
    def __init__(self, password):
        self.password = password.encode()
        self.salt = os.urandom(16)
    
    def derive_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.password)

# For those wondering, example usage

# ----- get key from pass --------
# key_derivation = KeyDerivation("my_password")
# key = key_derivation.derive_key()
# ----- Encryption / Decryption --------
# encryption_context = EncryptionContext(AESEncryption())
# encrypted_data = encryption_context.encrypt(key, b"My secret data")
# decrypted_data = encryption_context.decrypt(key, encrypted_data)
