from encryption import EncryptionContext, AESEncryption, KeyDerivation
import threading
import base64

class KeyManagementModule:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, master_password):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(KeyManagementModule, cls).__new__(cls)
                    cls._instance._initialize(master_password)
        return cls._instance

    def _initialize(self, master_password):
        key_derivation = KeyDerivation(master_password)
        self.master_key = key_derivation.derive_key()
        self.encryption_context = EncryptionContext(AESEncryption())
        
    def encrypt_key(self, key):
        return self.encryption_context.encrypt(self.master_key, key)
    
    def decrypt_key(self, key):
        return self.encryption_context.decrypt(self.master_key, key)

    def encrypt_filename(self, filename):
        return self.encryption_context.encrypt(self.master_key, filename.encode()).hex()

    def decrypt_filename(self, encrypted_filename):
        return self.encryption_context.decrypt(self.master_key, bytes.fromhex(encrypted_filename)).decode()
    
if __name__ == "__main__":
    import os
    key_manager = KeyManagementModule("master_password")
    key = os.urandom(32)  # example key to be encrypted
    encrypted_key = key_manager.encrypt_key(key)
    decrypted_key = key_manager.decrypt_key(encrypted_key)
    assert key == decrypted_key
    print("Key encryption and decryption successful.")