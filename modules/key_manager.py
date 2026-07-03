"""
Key Manager Module
==================

Key generation, storage, and management operations.
"""

import os
import re
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List

from .crypto_engine import CryptoEngine
from .utils import ensure_directory, calculate_hash

# Project root for relative paths
PROJECT_ROOT = Path(__file__).parent.parent


class KeyManager:
    """
    Manages encryption key generation, storage, and retrieval.
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize the key manager.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.file_config = self.config.get('files', {})
        
        # Key storage directory (relative to project root)
        keys_dir = self.file_config.get('keys_dir', 'keys')
        self.keys_dir = str(PROJECT_ROOT / keys_dir)
        ensure_directory(self.keys_dir)
        
        # Crypto engine
        self.crypto_engine = CryptoEngine(config)
        
        # Thread lock for registry access
        self._registry_lock = threading.Lock()
        
        # Key registry file
        self.registry_file = os.path.join(self.keys_dir, 'key_registry.json')
        self._load_registry()
    
    def _load_registry(self):
        """Load the key registry from file."""
        with self._registry_lock:
            if os.path.exists(self.registry_file):
                with open(self.registry_file, 'r') as f:
                    self.registry = json.load(f)
            else:
                self.registry = {}
    
    def _save_registry(self):
        """Save the key registry to file."""
        with self._registry_lock:
            with open(self.registry_file, 'w') as f:
                json.dump(self.registry, f, indent=2)
    
    def _sanitize_key_name(self, name: str) -> str:
        """
        Sanitize key name for safe use in file paths.
        
        Args:
            name: Key name to sanitize
            
        Returns:
            Sanitized key name
        """
        sanitized = re.sub(r'[^\w\-]', '_', name)
        sanitized = re.sub(r'_+', '_', sanitized).strip('_')
        if not sanitized:
            raise ValueError("Key name contains no valid characters")
        return sanitized
    
    # ==================== Key Generation ====================
    
    def generate_aes_key(self, name: str, password: str = None, 
                        key_size: int = 256) -> Dict:
        """
        Generate and store an AES key.
        
        Args:
            name: Key name/identifier
            password: Optional password to encrypt the key
            key_size: Key size in bits
            
        Returns:
            Key information dictionary
        """
        name = self._sanitize_key_name(name)
        
        # Generate key
        key = self.crypto_engine.generate_aes_key(key_size)
        
        # Create key info
        key_info = {
            'name': name,
            'algorithm': 'aes',
            'key_size': key_size,
            'created_at': datetime.now().isoformat(),
            'key_hash': calculate_hash(key, 'sha256')[:16]
        }
        
        # Save key
        if password:
            # Encrypt key with password
            encrypted_key = self.crypto_engine.encrypt_with_password(key, password, 'aes')
            key_file = os.path.join(self.keys_dir, f"{name}.enc")
            
            with open(key_file, 'w') as f:
                json.dump(encrypted_key, f)
            
            key_info['encrypted'] = True
            key_info['key_file'] = key_file
        else:
            # Save key directly (base64 encoded)
            key_file = os.path.join(self.keys_dir, f"{name}.key")
            
            with open(key_file, 'wb') as f:
                f.write(key)
            
            key_info['encrypted'] = False
            key_info['key_file'] = key_file
        
        # Register key
        with self._registry_lock:
            self.registry[name] = key_info
            self._save_registry()
        
        return key_info
    
    def generate_fernet_key(self, name: str, password: str = None) -> Dict:
        """
        Generate and store a Fernet key.
        
        Args:
            name: Key name/identifier
            password: Optional password to encrypt the key
            
        Returns:
            Key information dictionary
        """
        name = self._sanitize_key_name(name)
        
        # Generate key
        key = self.crypto_engine.generate_fernet_key()
        
        # Create key info
        key_info = {
            'name': name,
            'algorithm': 'fernet',
            'created_at': datetime.now().isoformat(),
            'key_hash': calculate_hash(key, 'sha256')[:16]
        }
        
        # Save key
        if password:
            # Encrypt key with password
            encrypted_key = self.crypto_engine.encrypt_with_password(key, password, 'aes')
            key_file = os.path.join(self.keys_dir, f"{name}.enc")
            
            with open(key_file, 'w') as f:
                json.dump(encrypted_key, f)
            
            key_info['encrypted'] = True
            key_info['key_file'] = key_file
        else:
            # Save key directly
            key_file = os.path.join(self.keys_dir, f"{name}.key")
            
            with open(key_file, 'wb') as f:
                f.write(key)
            
            key_info['encrypted'] = False
            key_info['key_file'] = key_file
        
        # Register key
        with self._registry_lock:
            self.registry[name] = key_info
            self._save_registry()
        
        return key_info
    
    def generate_rsa_keypair(self, name: str, password: str = None,
                            key_size: int = 2048) -> Dict:
        """
        Generate and store an RSA key pair.
        
        Args:
            name: Key name/identifier
            password: Optional password to encrypt the private key
            key_size: Key size in bits
            
        Returns:
            Key information dictionary
        """
        name = self._sanitize_key_name(name)
        
        # Generate key pair
        private_key, public_key = self.crypto_engine.generate_rsa_keypair(key_size)
        
        # Create key info
        key_info = {
            'name': name,
            'algorithm': 'rsa',
            'key_size': key_size,
            'created_at': datetime.now().isoformat(),
            'private_key_hash': calculate_hash(private_key, 'sha256')[:16],
            'public_key_hash': calculate_hash(public_key, 'sha256')[:16]
        }
        
        # Save public key (always unencrypted)
        public_key_file = os.path.join(self.keys_dir, f"{name}_public.pem")
        with open(public_key_file, 'wb') as f:
            f.write(public_key)
        
        key_info['public_key_file'] = public_key_file
        
        # Save private key
        if password:
            # Encrypt private key with password
            encrypted_key = self.crypto_engine.encrypt_with_password(private_key, password, 'aes')
            private_key_file = os.path.join(self.keys_dir, f"{name}_private.enc")
            
            with open(private_key_file, 'w') as f:
                json.dump(encrypted_key, f)
            
            key_info['encrypted'] = True
            key_info['private_key_file'] = private_key_file
        else:
            # Save private key directly
            private_key_file = os.path.join(self.keys_dir, f"{name}_private.pem")
            
            with open(private_key_file, 'wb') as f:
                f.write(private_key)
            
            key_info['encrypted'] = False
            key_info['private_key_file'] = private_key_file
        
        # Register key
        with self._registry_lock:
            self.registry[name] = key_info
            self._save_registry()
        
        return key_info
    
    # ==================== Key Retrieval ====================
    
    def get_key(self, name: str, password: str = None) -> Optional[bytes]:
        """
        Retrieve a stored key.
        
        Args:
            name: Key name/identifier
            password: Password if key is encrypted
            
        Returns:
            Key bytes or None
        """
        if name not in self.registry:
            return None
        
        key_info = self.registry[name]
        key_file = key_info.get('key_file')
        
        if not key_file or not os.path.exists(key_file):
            return None
        
        if key_info.get('encrypted', False):
            if not password:
                return None
            
            with open(key_file, 'r') as f:
                encrypted_key = json.load(f)
            
            return self.crypto_engine.decrypt_with_password(encrypted_key, password)
        else:
            with open(key_file, 'rb') as f:
                return f.read()
    
    def get_rsa_private_key(self, name: str, password: str = None) -> Optional[bytes]:
        """
        Retrieve an RSA private key.
        
        Args:
            name: Key name/identifier
            password: Password if key is encrypted
            
        Returns:
            Private key PEM bytes or None
        """
        if name not in self.registry:
            return None
        
        key_info = self.registry[name]
        private_key_file = key_info.get('private_key_file')
        
        if not private_key_file or not os.path.exists(private_key_file):
            return None
        
        if key_info.get('encrypted', False):
            if not password:
                return None
            
            with open(private_key_file, 'r') as f:
                encrypted_key = json.load(f)
            
            return self.crypto_engine.decrypt_with_password(encrypted_key, password)
        else:
            with open(private_key_file, 'rb') as f:
                return f.read()
    
    def get_rsa_public_key(self, name: str) -> Optional[bytes]:
        """
        Retrieve an RSA public key.
        
        Args:
            name: Key name/identifier
            
        Returns:
            Public key PEM bytes or None
        """
        if name not in self.registry:
            return None
        
        key_info = self.registry[name]
        public_key_file = key_info.get('public_key_file')
        
        if not public_key_file or not os.path.exists(public_key_file):
            return None
        
        with open(public_key_file, 'rb') as f:
            return f.read()
    
    # ==================== Key Management ====================
    
    def list_keys(self) -> List[Dict]:
        """
        List all stored keys.
        
        Returns:
            List of key information dictionaries
        """
        keys = []
        for name, info in self.registry.items():
            key_info = {
                'name': name,
                'algorithm': info.get('algorithm', 'unknown'),
                'created_at': info.get('created_at', 'unknown'),
                'encrypted': info.get('encrypted', False)
            }
            
            if 'key_size' in info:
                key_info['key_size'] = info['key_size']
            
            keys.append(key_info)
        
        return keys
    
    def delete_key(self, name: str) -> bool:
        """
        Delete a stored key.
        
        Args:
            name: Key name/identifier
            
        Returns:
            True if successful
        """
        with self._registry_lock:
            if name not in self.registry:
                return False
            
            key_info = self.registry[name]
            
            # Delete key files
            for key_file in ['key_file', 'private_key_file', 'public_key_file']:
                file_path = key_info.get(key_file)
                if file_path and os.path.exists(file_path):
                    os.remove(file_path)
            
            # Remove from registry
            del self.registry[name]
            self._save_registry()
        
        return True
    
    def key_exists(self, name: str) -> bool:
        """
        Check if a key exists.
        
        Args:
            name: Key name/identifier
            
        Returns:
            True if key exists
        """
        return name in self.registry
    
    def get_key_info(self, name: str) -> Optional[Dict]:
        """
        Get information about a key.
        
        Args:
            name: Key name/identifier
            
        Returns:
            Key information dictionary or None
        """
        return self.registry.get(name)
