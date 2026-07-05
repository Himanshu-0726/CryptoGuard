#!/usr/bin/env python3
"""
CryptoGuard - Encryption / Decryption Tool
===========================================

A comprehensive encryption tool for securing text and files using
AES, Fernet, and RSA algorithms.

IMPORTANT: Use encryption ethically and responsibly.
Always keep your encryption keys safe. Losing the key means
you cannot decrypt your data.

Usage:
    python encryptor.py --accept-terms [options]

Options:
    --accept-terms          Accept legal terms (required)
    --gui                   Launch GUI interface
    --encrypt TEXT          Encrypt text
    --decrypt TEXT          Decrypt text
    --encrypt-file FILE     Encrypt a file
    --decrypt-file FILE     Decrypt a file
    --algorithm ALG         Encryption algorithm (aes, fernet, rsa)
    --password PASS         Encryption/decryption password
    --generate-key NAME     Generate and save a key
    --list-keys             List all stored keys
    --list-algorithms       List available algorithms
"""

import sys
import argparse
import getpass
from pathlib import Path

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    print("Warning: PyYAML not installed. Using default config.")

from modules.crypto_engine import CryptoEngine
from modules.key_manager import KeyManager
from modules.file_handler import FileHandler
from modules.logger import Logger
from modules.utils import copy_to_clipboard, validate_password


class CryptoGuard:
    """
    Main application class for CryptoGuard.
    """
    
    def __init__(self, config: dict = None):
        """
        Initialize CryptoGuard.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Initialize components with shared key_manager
        self.logger = Logger(self.config)
        self.crypto_engine = CryptoEngine(self.config)
        self.key_manager = KeyManager(self.config)
        self.file_handler = FileHandler(self.config, self.key_manager)
    
    # ==================== Text Operations ====================
    
    def encrypt_text(self, text: str, password: str, algorithm: str = 'aes',
                     rsa_key_name: str = None) -> str:
        """
        Encrypt text.
        
        Args:
            text: Text to encrypt
            password: Encryption password
            algorithm: Encryption algorithm
            rsa_key_name: RSA key name (required for RSA algorithm)
            
        Returns:
            Encrypted text (base64 encoded)
        """
        try:
            rsa_public_key_pem = None
            if algorithm.lower() == 'rsa':
                if rsa_key_name:
                    rsa_public_key_pem = self.key_manager.get_rsa_public_key(rsa_key_name)
                if not rsa_public_key_pem:
                    raise ValueError("RSA public key required. Generate one with --generate-key NAME --algorithm rsa")
            
            encrypted = self.crypto_engine.encrypt_text(text, password, algorithm, True,
                                                        rsa_public_key_pem=rsa_public_key_pem)
            
            # Log operation
            self.logger.log_operation(
                operation_type='encrypt',
                algorithm=algorithm,
                file_size=len(text.encode()),
                details={'text_length': len(text)}
            )
            
            return encrypted
        except Exception as e:
            self.logger.log_error(f"Encryption failed: {e}")
            raise
    
    def decrypt_text(self, encrypted_text: str, password: str, algorithm: str = 'aes',
                     rsa_key_name: str = None) -> str:
        """
        Decrypt text.
        
        Args:
            encrypted_text: Encrypted text
            password: Decryption password
            algorithm: Encryption algorithm
            rsa_key_name: RSA key name (required for RSA algorithm)
            
        Returns:
            Decrypted text
        """
        try:
            rsa_private_key_pem = None
            rsa_key_password = None
            if algorithm.lower() == 'rsa':
                if rsa_key_name:
                    rsa_private_key_pem = self.key_manager.get_rsa_private_key(rsa_key_name)
                if not rsa_private_key_pem:
                    raise ValueError("RSA private key required. Generate one with --generate-key NAME --algorithm rsa")
            
            decrypted = self.crypto_engine.decrypt_text(encrypted_text, password, algorithm, True,
                                                        rsa_private_key_pem=rsa_private_key_pem,
                                                        rsa_key_password=rsa_key_password)
            
            # Log operation
            self.logger.log_operation(
                operation_type='decrypt',
                algorithm=algorithm,
                details={'text_length': len(decrypted)}
            )
            
            return decrypted
        except Exception as e:
            self.logger.log_error(f"Decryption failed: {e}")
            raise
    
    # ==================== File Operations ====================
    
    def encrypt_file(self, input_file: str, password: str, 
                    algorithm: str = 'aes', key_name: str = None) -> dict:
        """
        Encrypt a file.
        
        Args:
            input_file: Path to file to encrypt
            password: Encryption password
            algorithm: Encryption algorithm
            key_name: Key name for RSA encryption
            
        Returns:
            Encryption result dictionary
        """
        try:
            result = self.file_handler.encrypt_file(input_file, password, algorithm,
                                                     key_name=key_name)
            
            # Log operation
            self.logger.log_operation(
                operation_type='encrypt',
                algorithm=algorithm,
                file_name=input_file,
                file_size=result.get('original_size', 0),
                details=result
            )
            
            return result
        except Exception as e:
            self.logger.log_error(f"File encryption failed: {e}")
            raise
    
    def decrypt_file(self, input_file: str, password: str) -> dict:
        """
        Decrypt a file.
        
        Args:
            input_file: Path to encrypted file
            password: Decryption password
            
        Returns:
            Decryption result dictionary
        """
        try:
            result = self.file_handler.decrypt_file(input_file, password)
            
            # Log operation
            self.logger.log_operation(
                operation_type='decrypt',
                file_name=input_file,
                file_size=result.get('decrypted_size', 0),
                details=result
            )
            
            return result
        except Exception as e:
            self.logger.log_error(f"File decryption failed: {e}")
            raise
    
    # ==================== Key Operations ====================
    
    def generate_key(self, name: str, algorithm: str = 'aes',
                    password: str = None, key_size: int = None) -> dict:
        """
        Generate and store an encryption key.
        
        Args:
            name: Key name
            algorithm: Algorithm (aes, fernet, rsa)
            password: Optional password to encrypt the key
            key_size: Key size in bits
            
        Returns:
            Key information dictionary
        """
        try:
            if algorithm.lower() == 'aes':
                result = self.key_manager.generate_aes_key(name, password, key_size or 256)
            elif algorithm.lower() == 'fernet':
                result = self.key_manager.generate_fernet_key(name, password)
            elif algorithm.lower() == 'rsa':
                result = self.key_manager.generate_rsa_keypair(name, password, key_size or 2048)
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            # Log operation
            self.logger.log_key_generation(
                key_name=name,
                algorithm=algorithm,
                key_size=key_size,
                encrypted=password is not None
            )
            
            return result
        except Exception as e:
            self.logger.log_error(f"Key generation failed: {e}")
            raise
    
    def list_keys(self) -> list:
        """
        List all stored keys.
        
        Returns:
            List of key information dictionaries
        """
        return self.key_manager.list_keys()
    
    # ==================== Display Methods ====================
    
    def show_algorithms(self):
        """Display available algorithms."""
        algorithms = self.crypto_engine.get_available_algorithms()
        
        print("\nAvailable Encryption Algorithms:")
        print("-" * 50)
        for name, description in algorithms.items():
            print(f"  {name.upper():<10} - {description}")
        print("-" * 50 + "\n")
    
    def show_help(self):
        """Display help information."""
        print("""
CryptoGuard - Encryption / Decryption Tool

Usage:
    python encryptor.py --accept-terms [options]

Text Encryption:
    --encrypt "text" --password "pass" --algorithm aes
    --decrypt "encrypted_text" --password "pass" --algorithm aes

File Encryption:
    --encrypt-file document.txt --password "pass"
    --decrypt-file document.txt.enc --password "pass"

Key Management:
    --generate-key mykey --algorithm aes --password "pass"
    --list-keys

Other:
    --list-algorithms
    --gui
        """)


def load_config(config_path: str = None) -> dict:
    """Load configuration from file."""
    if not YAML_AVAILABLE:
        return {}
    
    if config_path is None:
        # Try default locations relative to project root
        project_root = Path(__file__).parent
        config_path = str(project_root / 'config.yaml')
    
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"Error loading config: {e}")
        return {}


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='CryptoGuard - Encryption / Decryption Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt text
  python encryptor.py --accept-terms --encrypt "Hello World" --password mypass
  
  # Decrypt text
  python encryptor.py --accept-terms --decrypt "encrypted_text" --password mypass
  
  # Encrypt file
  python encryptor.py --accept-terms --encrypt-file document.txt --password mypass
  
  # Generate key
  python encryptor.py --accept-terms --generate-key mykey --algorithm aes
  
  # Launch GUI
  python encryptor.py --accept-terms --gui
        """
    )
    
    parser.add_argument('--accept-terms', action='store_true',
                       help='Accept legal terms (required)')
    
    parser.add_argument('--gui', action='store_true',
                       help='Launch GUI interface')
    
    parser.add_argument('--encrypt', type=str,
                       help='Encrypt text')
    
    parser.add_argument('--decrypt', type=str,
                       help='Decrypt text')
    
    parser.add_argument('--encrypt-file', type=str,
                       help='Encrypt a file')
    
    parser.add_argument('--decrypt-file', type=str,
                       help='Decrypt a file')
    
    parser.add_argument('--algorithm', '-a', type=str, default='aes',
                       choices=['aes', 'fernet', 'rsa'],
                       help='Encryption algorithm (default: aes)')
    
    parser.add_argument('--password', '-p', type=str,
                       help='Encryption/decryption password')
    
    parser.add_argument('--generate-key', type=str,
                       help='Generate and save a key')
    
    parser.add_argument('--key-name', type=str,
                       help='Key name for file encryption')
    
    parser.add_argument('--list-keys', action='store_true',
                       help='List all stored keys')
    
    parser.add_argument('--list-algorithms', action='store_true',
                       help='List available algorithms')
    
    parser.add_argument('--output', '-o', type=str,
                       help='Output file')
    
    parser.add_argument('--config', '-c', type=str,
                       help='Config file path')
    
    parser.add_argument('--clipboard', action='store_true',
                       help='Copy result to clipboard')
    
    args = parser.parse_args()
    
    # Check for terms acceptance
    if not args.accept_terms:
        print("\n" + "="*60)
        print("  ERROR: You must accept the legal terms to use this tool.")
        print("="*60)
        print("\n  Usage: python encryptor.py --accept-terms [options]")
        print("\n  Use encryption ethically and responsibly.")
        print("  Always keep your encryption keys safe.")
        print("="*60 + "\n")
        sys.exit(1)
    
    # Load configuration
    config = load_config(args.config)
    
    # Initialize CryptoGuard
    app = CryptoGuard(config)
    
    # Print banner and legal notice
    app.logger.print_banner()
    app.logger.print_legal_notice()
    
    # Launch GUI if requested
    if args.gui:
        try:
            from gui import CryptoGuardGUI
            gui = CryptoGuardGUI(config)
            gui.run()
        except ImportError as e:
            app.logger.print_error(f"GUI not available: {e}")
            sys.exit(1)
        return
    
    # List algorithms
    if args.list_algorithms:
        app.show_algorithms()
        return
    
    # List keys
    if args.list_keys:
        keys = app.list_keys()
        if not keys:
            app.logger.print_info("No keys stored yet.")
        else:
            print("\nStored Keys:")
            print("-" * 50)
            for key in keys:
                print(f"  {key['name']:<20} {key['algorithm'].upper():<10} Created: {key['created_at'][:10]}")
            print("-" * 50 + "\n")
        return
    
    # Generate key
    if args.generate_key:
        # Get password
        password = args.password
        if not password:
            password = getpass.getpass("Enter password to encrypt the key: ")
        
        if not password:
            app.logger.print_error("Password is required to protect stored keys.")
            sys.exit(1)
        
        try:
            result = app.generate_key(args.generate_key, args.algorithm, password)
            app.logger.print_success(f"Key '{args.generate_key}' generated successfully!")
            print(f"  Algorithm: {result.get('algorithm', 'unknown')}")
            print(f"  Created: {result.get('created_at', 'unknown')}")
        except Exception as e:
            app.logger.print_error(f"Failed to generate key: {e}")
        return
    
    # Encrypt text
    if args.encrypt:
        # Get password if not provided
        password = args.password
        if not password:
            password = getpass.getpass("Enter encryption password: ")
        
        if not password:
            app.logger.print_error("Password is required for encryption.")
            sys.exit(1)
        
        # Validate password
        is_valid, message = validate_password(password)
        if not is_valid:
            app.logger.print_warning(f"Password validation: {message}")
        
        try:
            encrypted = app.encrypt_text(args.encrypt, password, args.algorithm,
                                         rsa_key_name=args.key_name)
            app.logger.print_success("Text encrypted successfully!")
            print(f"\nEncrypted text:\n{encrypted}\n")
            
            # Copy to clipboard if requested
            if args.clipboard:
                if copy_to_clipboard(encrypted):
                    app.logger.print_success("Copied to clipboard!")
                else:
                    app.logger.print_warning("Failed to copy to clipboard.")
            
            # Save to file if output specified
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(encrypted)
                app.logger.print_success(f"Saved to {args.output}")
                
        except Exception as e:
            app.logger.print_error(f"Encryption failed: {e}")
        return
    
    # Decrypt text
    if args.decrypt:
        # Get password if not provided
        password = args.password
        if not password:
            password = getpass.getpass("Enter decryption password: ")
        
        if not password:
            app.logger.print_error("Password is required for decryption.")
            sys.exit(1)
        
        try:
            decrypted = app.decrypt_text(args.decrypt, password, args.algorithm,
                                         rsa_key_name=args.key_name)
            app.logger.print_success("Text decrypted successfully!")
            print(f"\nDecrypted text:\n{decrypted}\n")
            
            # Copy to clipboard if requested
            if args.clipboard:
                if copy_to_clipboard(decrypted):
                    app.logger.print_success("Copied to clipboard!")
                else:
                    app.logger.print_warning("Failed to copy to clipboard.")
            
            # Save to file if output specified
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(decrypted)
                app.logger.print_success(f"Saved to {args.output}")
                
        except Exception as e:
            app.logger.print_error(f"Decryption failed: {e}")
        return
    
    # Encrypt file
    if args.encrypt_file:
        # Get password if not provided
        password = args.password
        if not password:
            password = getpass.getpass("Enter encryption password: ")
        
        if not password:
            app.logger.print_error("Password is required for encryption.")
            sys.exit(1)
        
        try:
            result = app.encrypt_file(args.encrypt_file, password, args.algorithm,
                                      key_name=args.key_name)
            app.logger.print_success("File encrypted successfully!")
            print(f"  Input: {result['input_file']}")
            print(f"  Output: {result['output_file']}")
            print(f"  Original size: {result['original_size']:,} bytes")
            print(f"  Encrypted size: {result['encrypted_size']:,} bytes")
            print(f"  Algorithm: {result.get('algorithm', args.algorithm).upper()}")
        except Exception as e:
            app.logger.print_error(f"File encryption failed: {e}")
        return
    
    # Decrypt file
    if args.decrypt_file:
        # Get password if not provided
        password = args.password
        if not password:
            password = getpass.getpass("Enter decryption password: ")
        
        if not password:
            app.logger.print_error("Password is required for decryption.")
            sys.exit(1)
        
        try:
            result = app.decrypt_file(args.decrypt_file, password)
            app.logger.print_success("File decrypted successfully!")
            print(f"  Input: {result['input_file']}")
            print(f"  Output: {result['output_file']}")
            print(f"  Original name: {result['original_name']}")
        except Exception as e:
            app.logger.print_error(f"File decryption failed: {e}")
        return
    
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser.print_help()


if __name__ == '__main__':
    main()
