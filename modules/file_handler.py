"""
File Handler Module
===================

File encryption and decryption operations.
"""

import os
import json
import base64
import shutil
from pathlib import Path
from typing import Dict, Optional, List, Tuple

from .crypto_engine import CryptoEngine
from .key_manager import KeyManager
from .utils import ensure_directory, format_file_size, secure_delete_file


class FileHandler:
    """
    Handles file encryption and decryption operations.
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize the file handler.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.file_config = self.config.get('files', {})
        
        # Directories
        self.encrypted_dir = self.file_config.get('encrypted_dir', 'encrypted')
        self.temp_dir = self.file_config.get('temp_dir', 'temp')
        self.encrypted_extension = self.file_config.get('encrypted_extension', '.enc')
        self.backup_original = self.file_config.get('backup_original', True)
        
        # Ensure directories exist
        ensure_directory(self.encrypted_dir)
        ensure_directory(self.temp_dir)
        
        # Initialize components
        self.crypto_engine = CryptoEngine(config)
        self.key_manager = KeyManager(config)
    
    # ==================== File Encryption ====================
    
    def encrypt_file(self, input_file: str, password: str = None,
                    algorithm: str = 'aes', key_name: str = None,
                    output_file: str = None) -> Dict:
        """
        Encrypt a file.
        
        Args:
            input_file: Path to file to encrypt
            password: Password for encryption
            algorithm: Encryption algorithm
            key_name: Key name (if using stored key)
            output_file: Output file path
            
        Returns:
            Encryption result dictionary
        """
        # Validate input file
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        # Read file data
        with open(input_file, 'rb') as f:
            file_data = f.read()
        
        # Get original filename
        original_name = os.path.basename(input_file)
        
        # Create metadata
        metadata = {
            'original_name': original_name,
            'original_size': len(file_data),
            'algorithm': algorithm
        }
        
        # Encrypt data
        if password:
            encrypted_result = self.crypto_engine.encrypt_with_password(
                file_data, password, algorithm
            )
        elif key_name:
            # Get key from key manager
            key = self.key_manager.get_key(key_name, password)
            if not key:
                raise ValueError(f"Key not found: {key_name}")
            
            # Encrypt with key
            if algorithm.lower() == 'aes':
                encrypted_data = self.crypto_engine.encrypt_aes(file_data, key)
                encrypted_result = {
                    'algorithm': 'aes-256-cbc',
                    'ciphertext': base64.b64encode(encrypted_data).decode()
                }
            elif algorithm.lower() == 'fernet':
                encrypted_data = self.crypto_engine.encrypt_fernet(file_data, key)
                encrypted_result = {
                    'algorithm': 'fernet',
                    'ciphertext': encrypted_data.decode()
                }
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
        else:
            raise ValueError("Either password or key_name must be provided")
        
        # Add metadata to result
        encrypted_result['metadata'] = metadata
        
        # Determine output file
        if output_file is None:
            base_name = os.path.basename(input_file)
            output_file = os.path.join(
                self.encrypted_dir,
                f"{base_name}{self.encrypted_extension}"
            )
        
        # Ensure output directory exists
        ensure_directory(os.path.dirname(output_file) or '.')
        
        # Save encrypted file
        with open(output_file, 'w') as f:
            json.dump(encrypted_result, f, indent=2)
        
        # Backup original if configured
        if self.backup_original:
            backup_dir = os.path.join(self.encrypted_dir, 'backups')
            ensure_directory(backup_dir)
            backup_file = os.path.join(backup_dir, original_name)
            shutil.copy2(input_file, backup_file)
        
        # Get file sizes
        original_size = os.path.getsize(input_file)
        encrypted_size = os.path.getsize(output_file)
        
        return {
            'success': True,
            'input_file': input_file,
            'output_file': output_file,
            'original_size': original_size,
            'encrypted_size': encrypted_size,
            'compression_ratio': encrypted_size / original_size if original_size > 0 else 0,
            'algorithm': algorithm
        }
    
    def encrypt_file_with_key(self, input_file: str, key_file: str,
                             algorithm: str = 'aes', output_file: str = None) -> Dict:
        """
        Encrypt a file using a key file.
        
        Args:
            input_file: Path to file to encrypt
            key_file: Path to key file
            algorithm: Encryption algorithm
            output_file: Output file path
            
        Returns:
            Encryption result dictionary
        """
        # Validate input files
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Input file not found: {input_file}")
        if not os.path.exists(key_file):
            raise FileNotFoundError(f"Key file not found: {key_file}")
        
        # Read file data
        with open(input_file, 'rb') as f:
            file_data = f.read()
        
        # Read key
        with open(key_file, 'rb') as f:
            key = f.read()
        
        # Get original filename
        original_name = os.path.basename(input_file)
        
        # Create metadata
        metadata = {
            'original_name': original_name,
            'original_size': len(file_data),
            'algorithm': algorithm
        }
        
        # Encrypt with key
        if algorithm.lower() == 'aes':
            encrypted_data = self.crypto_engine.encrypt_aes(file_data, key)
            encrypted_result = {
                'algorithm': 'aes-256-cbc',
                'ciphertext': base64.b64encode(encrypted_data).decode(),
                'metadata': metadata
            }
        elif algorithm.lower() == 'fernet':
            encrypted_data = self.crypto_engine.encrypt_fernet(file_data, key)
            encrypted_result = {
                'algorithm': 'fernet',
                'ciphertext': base64.b64encode(encrypted_data).decode(),
                'metadata': metadata
            }
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Determine output file
        if output_file is None:
            base_name = os.path.basename(input_file)
            output_file = os.path.join(
                self.encrypted_dir,
                f"{base_name}{self.encrypted_extension}"
            )
        
        # Ensure output directory exists
        ensure_directory(os.path.dirname(output_file) or '.')
        
        # Save encrypted file
        with open(output_file, 'w') as f:
            json.dump(encrypted_result, f, indent=2)
        
        return {
            'success': True,
            'input_file': input_file,
            'output_file': output_file,
            'original_size': os.path.getsize(input_file),
            'encrypted_size': os.path.getsize(output_file),
            'algorithm': algorithm
        }
    
    # ==================== File Decryption ====================
    
    def decrypt_file(self, input_file: str, password: str = None,
                    key_name: str = None, output_file: str = None) -> Dict:
        """
        Decrypt a file.
        
        Args:
            input_file: Path to encrypted file
            password: Password for decryption
            key_name: Key name (if using stored key)
            output_file: Output file path
            
        Returns:
            Decryption result dictionary
        """
        # Validate input file
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        # Read encrypted file
        with open(input_file, 'r') as f:
            encrypted_data = json.load(f)
        
        # Extract metadata
        metadata = encrypted_data.get('metadata', {})
        original_name = metadata.get('original_name', 'decrypted_file')
        algorithm = encrypted_data.get('algorithm', 'aes-256-cbc')
        
        # Decrypt data
        if password:
            decrypted_data = self.crypto_engine.decrypt_with_password(
                encrypted_data, password
            )
        elif key_name:
            # Get key from key manager
            key = self.key_manager.get_key(key_name, password)
            if not key:
                raise ValueError(f"Key not found: {key_name}")
            
            # Decrypt with key
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            
            if 'aes' in algorithm.lower():
                decrypted_data = self.crypto_engine.decrypt_aes(ciphertext, key)
            elif 'fernet' in algorithm.lower():
                decrypted_data = self.crypto_engine.decrypt_fernet(ciphertext, key)
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
        else:
            raise ValueError("Either password or key_name must be provided")
        
        # Determine output file
        if output_file is None:
            output_file = os.path.join(
                os.path.dirname(input_file) or '.',
                original_name
            )
        
        # Ensure output directory exists
        ensure_directory(os.path.dirname(output_file) or '.')
        
        # Save decrypted file
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        
        return {
            'success': True,
            'input_file': input_file,
            'output_file': output_file,
            'encrypted_size': os.path.getsize(input_file),
            'decrypted_size': os.path.getsize(output_file),
            'original_name': original_name,
            'algorithm': algorithm
        }
    
    def decrypt_file_with_key(self, input_file: str, key_file: str,
                             output_file: str = None) -> Dict:
        """
        Decrypt a file using a key file.
        
        Args:
            input_file: Path to encrypted file
            key_file: Path to key file
            output_file: Output file path
            
        Returns:
            Decryption result dictionary
        """
        # Validate input files
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Input file not found: {input_file}")
        if not os.path.exists(key_file):
            raise FileNotFoundError(f"Key file not found: {key_file}")
        
        # Read encrypted file
        with open(input_file, 'r') as f:
            encrypted_data = json.load(f)
        
        # Read key
        with open(key_file, 'rb') as f:
            key = f.read()
        
        # Extract metadata
        metadata = encrypted_data.get('metadata', {})
        original_name = metadata.get('original_name', 'decrypted_file')
        algorithm = encrypted_data.get('algorithm', 'aes-256-cbc')
        
        # Decrypt with key
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        
        if 'aes' in algorithm.lower():
            decrypted_data = self.crypto_engine.decrypt_aes(ciphertext, key)
        elif 'fernet' in algorithm.lower():
            decrypted_data = self.crypto_engine.decrypt_fernet(ciphertext, key)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Determine output file
        if output_file is None:
            output_file = os.path.join(
                os.path.dirname(input_file) or '.',
                original_name
            )
        
        # Ensure output directory exists
        ensure_directory(os.path.dirname(output_file) or '.')
        
        # Save decrypted file
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        
        return {
            'success': True,
            'input_file': input_file,
            'output_file': output_file,
            'encrypted_size': os.path.getsize(input_file),
            'decrypted_size': os.path.getsize(output_file),
            'original_name': original_name,
            'algorithm': algorithm
        }
    
    # ==================== Batch Operations ====================
    
    def batch_encrypt(self, input_dir: str, password: str,
                     algorithm: str = 'aes', pattern: str = '*') -> List[Dict]:
        """
        Encrypt all files in a directory.
        
        Args:
            input_dir: Input directory
            password: Encryption password
            algorithm: Encryption algorithm
            pattern: File pattern to match
            
        Returns:
            List of encryption results
        """
        results = []
        input_path = Path(input_dir)
        
        for file_path in input_path.glob(pattern):
            if file_path.is_file():
                try:
                    result = self.encrypt_file(
                        str(file_path), password, algorithm
                    )
                    results.append(result)
                except Exception as e:
                    results.append({
                        'success': False,
                        'input_file': str(file_path),
                        'error': str(e)
                    })
        
        return results
    
    def batch_decrypt(self, input_dir: str, password: str,
                     pattern: str = '*.enc') -> List[Dict]:
        """
        Decrypt all encrypted files in a directory.
        
        Args:
            input_dir: Input directory
            password: Decryption password
            pattern: File pattern to match
            
        Returns:
            List of decryption results
        """
        results = []
        input_path = Path(input_dir)
        
        for file_path in input_path.glob(pattern):
            if file_path.is_file():
                try:
                    result = self.decrypt_file(
                        str(file_path), password
                    )
                    results.append(result)
                except Exception as e:
                    results.append({
                        'success': False,
                        'input_file': str(file_path),
                        'error': str(e)
                    })
        
        return results
    
    # ==================== File Information ====================
    
    def get_encrypted_file_info(self, file_path: str) -> Optional[Dict]:
        """
        Get information about an encrypted file.
        
        Args:
            file_path: Path to encrypted file
            
        Returns:
            File information dictionary or None
        """
        if not os.path.exists(file_path):
            return None
        
        try:
            with open(file_path, 'r') as f:
                encrypted_data = json.load(f)
            
            metadata = encrypted_data.get('metadata', {})
            
            return {
                'file_path': file_path,
                'file_size': os.path.getsize(file_path),
                'file_size_formatted': format_file_size(os.path.getsize(file_path)),
                'original_name': metadata.get('original_name', 'unknown'),
                'original_size': metadata.get('original_size', 0),
                'algorithm': encrypted_data.get('algorithm', 'unknown'),
                'is_encrypted': True
            }
        except Exception:
            return None
    
    def list_encrypted_files(self, directory: str = None) -> List[Dict]:
        """
        List all encrypted files in a directory.
        
        Args:
            directory: Directory to search (default: encrypted_dir)
            
        Returns:
            List of file information dictionaries
        """
        search_dir = directory or self.encrypted_dir
        results = []
        
        for file_path in Path(search_dir).glob(f'*{self.encrypted_extension}'):
            if file_path.is_file():
                info = self.get_encrypted_file_info(str(file_path))
                if info:
                    results.append(info)
        
        return results
    
    # ==================== Cleanup ====================
    
    def secure_delete(self, file_path: str) -> bool:
        """
        Securely delete a file.
        
        Args:
            file_path: Path to file to delete
            
        Returns:
            True if successful
        """
        return secure_delete_file(file_path)
    
    def cleanup_temp(self) -> int:
        """
        Clean up temporary files.
        
        Returns:
            Number of files deleted
        """
        count = 0
        for file_path in Path(self.temp_dir).glob('*'):
            if file_path.is_file():
                if secure_delete_file(str(file_path)):
                    count += 1
        
        return count
