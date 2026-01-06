from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import hashlib
import os

class FileEncryptor:
    def __init__(self, password="MySecurePassword123!"):
        # Generate a key from password using PBKDF2
        self.password = password.encode()
        
    def _get_key(self, salt):
        # Derive a 32-byte key from password
        key = PBKDF2(self.password, salt, dkLen=32, count=100000)
        return key
    
    def encrypt_file(self, file_data, filename):
        """Encrypt file data and return encrypted data with metadata"""
        # Generate random salt
        salt = get_random_bytes(16)
        
        # Derive key from password and salt
        key = self._get_key(salt)
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_EAX)
        
        # Encrypt the file data
        ciphertext, tag = cipher.encrypt_and_digest(file_data)
        
        # Return all components needed for decryption
        return {
            'salt': salt,
            'nonce': cipher.nonce,
            'tag': tag,
            'ciphertext': ciphertext,
            'filename': filename
        }
    
    def decrypt_file(self, encrypted_data):
        """Decrypt file data"""
        # Get key from salt
        key = self._get_key(encrypted_data['salt'])
        
        # Create cipher for decryption
        cipher = AES.new(key, AES.MODE_EAX, nonce=encrypted_data['nonce'])
        
        # Decrypt and verify
        plaintext = cipher.decrypt_and_verify(
            encrypted_data['ciphertext'], 
            encrypted_data['tag']
        )
        
        return plaintext
    
    def save_encrypted_file(self, encrypted_data, filepath):
        """Save encrypted file to disk"""
        with open(filepath, 'wb') as f:
            # Write salt (16 bytes)
            f.write(encrypted_data['salt'])
            # Write nonce (16 bytes)
            f.write(encrypted_data['nonce'])
            # Write tag (16 bytes)
            f.write(encrypted_data['tag'])
            # Write encrypted data
            f.write(encrypted_data['ciphertext'])
    
    def load_encrypted_file(self, filepath):
        """Load encrypted file from disk"""
        with open(filepath, 'rb') as f:
            salt = f.read(16)
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()
        
        return {
            'salt': salt,
            'nonce': nonce,
            'tag': tag,
            'ciphertext': ciphertext
        }