"""
Crypto Engine Module
====================

Core encryption and decryption operations using AES, Fernet, and RSA.
"""

import os
import base64
import secrets
from typing import Optional, Tuple, Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend


class CryptoEngine:
    """
    Core encryption and decryption engine supporting AES, Fernet, and RSA.
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize the crypto engine.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.enc_config = self.config.get('encryption', {})
        self.backend = default_backend()
        
        # Default settings
        self.aes_key_size = self.enc_config.get('aes_key_size', 256)
        self.rsa_key_size = self.enc_config.get('rsa_key_size', 2048)
        self.pbkdf2_iterations = self.enc_config.get('pbkdf2_iterations', 100000)
        self.salt_size = self.enc_config.get('salt_size', 16)
    
    # ==================== Key Generation ====================
    
    def generate_aes_key(self, key_size: int = None) -> bytes:
        """
        Generate a random AES key.
        
        Args:
            key_size: Key size in bits (128, 192, 256)
            
        Returns:
            AES key bytes
        """
        size = key_size or self.aes_key_size
        return secrets.token_bytes(size // 8)
    
    def generate_fernet_key(self) -> bytes:
        """
        Generate a Fernet key.
        
        Returns:
            Fernet key bytes
        """
        return Fernet.generate_key()
    
    def generate_rsa_keypair(self, key_size: int = None) -> Tuple[bytes, bytes]:
        """
        Generate RSA key pair.
        
        Args:
            key_size: Key size in bits
            
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        size = key_size or self.rsa_key_size
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=size,
            backend=self.backend
        )
        
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def derive_key_from_password(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        Derive an AES key from a password using PBKDF2.
        
        Args:
            password: Password string
            salt: Salt bytes (generated if not provided)
            
        Returns:
            Tuple of (key, salt)
        """
        if salt is None:
            salt = secrets.token_bytes(self.salt_size)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.pbkdf2_iterations,
            backend=self.backend
        )
        
        key = kdf.derive(password.encode())
        return key, salt
    
    def derive_key_scrypt(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        Derive an AES key from a password using Scrypt.
        
        Args:
            password: Password string
            salt: Salt bytes (generated if not provided)
            
        Returns:
            Tuple of (key, salt)
        """
        if salt is None:
            salt = secrets.token_bytes(self.salt_size)
        
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=self.backend
        )
        
        key = kdf.derive(password.encode())
        return key, salt
    
    # ==================== AES Encryption ====================
    
    def encrypt_aes(self, data: bytes, key: bytes) -> bytes:
        """
        Encrypt data using AES-256-CBC.
        
        Args:
            data: Data to encrypt
            key: AES key
            
        Returns:
            Encrypted data with IV prepended
        """
        # Generate random IV
        iv = secrets.token_bytes(16)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Pad data (PKCS7)
        pad_length = 16 - (len(data) % 16)
        padded_data = data + bytes([pad_length] * pad_length)
        
        # Encrypt
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + ciphertext
        return iv + ciphertext
    
    def decrypt_aes(self, encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypt AES-256-CBC encrypted data.
        
        Args:
            encrypted_data: Encrypted data with IV prepended
            key: AES key
            
        Returns:
            Decrypted data
        """
        # Extract IV
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        pad_length = padded_data[-1]
        data = padded_data[:-pad_length]
        
        return data
    
    # ==================== Fernet Encryption ====================
    
    def encrypt_fernet(self, data: bytes, key: bytes) -> bytes:
        """
        Encrypt data using Fernet.
        
        Args:
            data: Data to encrypt
            key: Fernet key
            
        Returns:
            Encrypted data
        """
        f = Fernet(key)
        return f.encrypt(data)
    
    def decrypt_fernet(self, encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypt Fernet encrypted data.
        
        Args:
            encrypted_data: Encrypted data
            key: Fernet key
            
        Returns:
            Decrypted data
        """
        f = Fernet(key)
        return f.decrypt(encrypted_data)
    
    # ==================== RSA Encryption ====================
    
    def encrypt_rsa(self, data: bytes, public_key_pem: bytes) -> bytes:
        """
        Encrypt data using RSA.
        
        Args:
            data: Data to encrypt
            public_key_pem: Public key in PEM format
            
        Returns:
            Encrypted data
        """
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=self.backend
        )
        
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return ciphertext
    
    def decrypt_rsa(self, encrypted_data: bytes, private_key_pem: bytes) -> bytes:
        """
        Decrypt RSA encrypted data.
        
        Args:
            encrypted_data: Encrypted data
            private_key_pem: Private key in PEM format
            
        Returns:
            Decrypted data
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=self.backend
        )
        
        plaintext = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext
    
    # ==================== Password-Based Encryption ====================
    
    def encrypt_with_password(self, data: bytes, password: str, 
                             algorithm: str = 'aes') -> Dict:
        """
        Encrypt data using a password.
        
        Args:
            data: Data to encrypt
            password: Password string
            algorithm: Algorithm to use (aes, fernet)
            
        Returns:
            Dictionary with encrypted data and metadata
        """
        if algorithm.lower() == 'aes':
            # Derive key from password
            key, salt = self.derive_key_from_password(password)
            
            # Encrypt data
            ciphertext = self.encrypt_aes(data, key)
            
            return {
                'algorithm': 'aes-256-cbc',
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'salt': base64.b64encode(salt).decode(),
                'iterations': self.pbkdf2_iterations
            }
            
        elif algorithm.lower() == 'fernet':
            # Derive key from password using scrypt
            key, salt = self.derive_key_scrypt(password)
            
            # Fernet requires URL-safe base64 key
            fernet_key = base64.urlsafe_b64encode(key)
            
            # Encrypt data
            ciphertext = self.encrypt_fernet(data, fernet_key)
            
            return {
                'algorithm': 'fernet',
                'ciphertext': ciphertext.decode(),
                'salt': base64.b64encode(salt).decode()
            }
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def decrypt_with_password(self, encrypted_info: Dict, password: str) -> bytes:
        """
        Decrypt data encrypted with a password.
        
        Args:
            encrypted_info: Dictionary with encrypted data
            password: Password string
            
        Returns:
            Decrypted data
        """
        algorithm = encrypted_info.get('algorithm', '').lower()
        ciphertext = base64.b64decode(encrypted_info['ciphertext'])
        salt = base64.b64decode(encrypted_info['salt'])
        
        if algorithm == 'aes-256-cbc':
            # Derive key from password
            key, _ = self.derive_key_from_password(password, salt)
            
            # Decrypt data
            return self.decrypt_aes(ciphertext, key)
            
        elif algorithm == 'fernet':
            # Derive key from password
            key, _ = self.derive_key_scrypt(password, salt)
            
            # Fernet requires URL-safe base64 key
            fernet_key = base64.urlsafe_b64encode(key)
            
            # Decrypt data
            return self.decrypt_fernet(ciphertext, fernet_key)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    # ==================== Utility Methods ====================
    
    def get_available_algorithms(self) -> Dict[str, str]:
        """
        Get list of available encryption algorithms.
        
        Returns:
            Dictionary of algorithm names and descriptions
        """
        return {
            'aes': 'AES-256-CBC - Industry standard symmetric encryption',
            'fernet': 'Fernet - Simple, secure symmetric encryption',
            'rsa': 'RSA-2048 - Asymmetric encryption (requires key pair)'
        }
    
    def encrypt_text(self, text: str, key_or_password: str, 
                    algorithm: str = 'aes', is_password: bool = True) -> str:
        """
        Encrypt text string.
        
        Args:
            text: Text to encrypt
            key_or_password: Encryption key or password
            algorithm: Algorithm to use
            is_password: True if key_or_password is a password
            
        Returns:
            Encrypted text (base64 encoded)
        """
        data = text.encode('utf-8')
        
        if is_password:
            result = self.encrypt_with_password(data, key_or_password, algorithm)
            return base64.b64encode(str(result).encode()).decode()
        else:
            # Direct key usage
            if algorithm.lower() == 'aes':
                key = base64.b64decode(key_or_password)
                encrypted = self.encrypt_aes(data, key)
                return base64.b64encode(encrypted).decode()
            elif algorithm.lower() == 'fernet':
                key = key_or_password.encode() if isinstance(key_or_password, str) else key_or_password
                encrypted = self.encrypt_fernet(data, key)
                return base64.b64encode(encrypted).decode()
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def decrypt_text(self, encrypted_text: str, key_or_password: str,
                    algorithm: str = 'aes', is_password: bool = True) -> str:
        """
        Decrypt text string.
        
        Args:
            encrypted_text: Encrypted text (base64 encoded)
            key_or_password: Decryption key or password
            algorithm: Algorithm to use
            is_password: True if key_or_password is a password
            
        Returns:
            Decrypted text
        """
        if is_password:
            encrypted_info = eval(base64.b64decode(encrypted_text).decode())
            decrypted = self.decrypt_with_password(encrypted_info, key_or_password)
            return decrypted.decode('utf-8')
        else:
            # Direct key usage
            encrypted_data = base64.b64decode(encrypted_text)
            
            if algorithm.lower() == 'aes':
                key = base64.b64decode(key_or_password)
                decrypted = self.decrypt_aes(encrypted_data, key)
                return decrypted.decode('utf-8')
            elif algorithm.lower() == 'fernet':
                key = key_or_password.encode() if isinstance(key_or_password, str) else key_or_password
                decrypted = self.decrypt_fernet(encrypted_data, key)
                return decrypted.decode('utf-8')
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
