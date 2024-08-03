from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

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