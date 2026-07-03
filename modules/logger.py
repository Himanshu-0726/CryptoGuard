"""
Logger Module
=============

Logging and audit trail operations.
"""

import os
import json
import sqlite3
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Optional
from pathlib import Path

# Project root for relative paths
PROJECT_ROOT = Path(__file__).parent.parent


class Color:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'


class Logger:
    """
    Comprehensive logging system with console, file, and SQLite support.
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize the logger.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.log_config = self.config.get('logging', {})
        
        # Setup directories (relative to project root)
        log_dir = self.log_config.get('log_dir', 'logs')
        self.log_dir = str(PROJECT_ROOT / log_dir)
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self._setup_file_logger()
        self._setup_sqlite()
        
        # Statistics
        self.stats = {
            'operations': 0,
            'encryptions': 0,
            'decryptions': 0,
            'key_generations': 0,
            'errors': 0,
            'start_time': datetime.now()
        }
    
    def _setup_file_logger(self):
        """Setup rotating file logger."""
        self.file_logger = logging.getLogger('CryptoGuard')
        self.file_logger.setLevel(getattr(logging, self.log_config.get('log_level', 'INFO').upper()))
        
        # Only setup handlers if not already configured
        if not self.file_logger.handlers:
            # File handler with rotation
            log_file = os.path.join(self.log_dir, 'CryptoGuard.log')
            max_bytes = self.log_config.get('max_log_size', 10) * 1024 * 1024
            backup_count = self.log_config.get('max_log_files', 5)
            
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )
            
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(formatter)
            self.file_logger.addHandler(file_handler)
            
            # Console handler
            if self.log_config.get('console', True):
                console_handler = logging.StreamHandler()
                console_handler.setFormatter(formatter)
                self.file_logger.addHandler(console_handler)
    
    def _setup_sqlite(self):
        """Setup SQLite database for audit trail."""
        self.db_enabled = self.log_config.get('sqlite', True)
        
        if self.db_enabled:
            db_path = os.path.join(self.log_dir, 'CryptoGuard.db')
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            self.cursor = self.conn.cursor()
            self._create_tables()
    
    def _create_tables(self):
        """Create SQLite tables."""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                operation_type TEXT NOT NULL,
                algorithm TEXT,
                file_name TEXT,
                file_size INTEGER,
                success INTEGER DEFAULT 1,
                error_message TEXT,
                details TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                key_name TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                key_size INTEGER,
                encrypted INTEGER DEFAULT 0
            )
        ''')
        
        self.conn.commit()
    
    # ==================== Logging Operations ====================
    
    def log_operation(self, operation_type: str, algorithm: str = None,
                     file_name: str = None, file_size: int = None,
                     success: bool = True, error_message: str = None,
                     details: Dict = None):
        """
        Log an encryption/decryption operation.
        
        Args:
            operation_type: Type of operation (encrypt, decrypt, etc.)
            algorithm: Algorithm used
            file_name: File name (if file operation)
            file_size: File size in bytes
            success: Whether operation was successful
            error_message: Error message if failed
            details: Additional details
        """
        self.stats['operations'] += 1
        
        if operation_type == 'encrypt':
            self.stats['encryptions'] += 1
        elif operation_type == 'decrypt':
            self.stats['decryptions'] += 1
        
        if not success:
            self.stats['errors'] += 1
        
        # Log to file
        level = logging.INFO if success else logging.ERROR
        message = f"{operation_type.upper()} - Algorithm: {algorithm}"
        if file_name:
            message += f" - File: {file_name}"
        if error_message:
            message += f" - Error: {error_message}"
        
        self.file_logger.log(level, message)
        
        # Log to SQLite
        if self.db_enabled:
            self.cursor.execute('''
                INSERT INTO operations (timestamp, operation_type, algorithm,
                                       file_name, file_size, success,
                                       error_message, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                operation_type,
                algorithm,
                file_name,
                file_size,
                1 if success else 0,
                error_message,
                json.dumps(details) if details else None
            ))
            self.conn.commit()
    
    def log_key_generation(self, key_name: str, algorithm: str,
                          key_size: int = None, encrypted: bool = False):
        """
        Log a key generation operation.
        
        Args:
            key_name: Key name
            algorithm: Algorithm used
            key_size: Key size in bits
            encrypted: Whether key is encrypted
        """
        self.stats['key_generations'] += 1
        
        # Log to file
        message = f"KEY GENERATED - Name: {key_name} - Algorithm: {algorithm}"
        if key_size:
            message += f" - Size: {key_size}"
        message += f" - Encrypted: {encrypted}"
        
        self.file_logger.info(message)
        
        # Log to SQLite
        if self.db_enabled:
            self.cursor.execute('''
                INSERT INTO keys (timestamp, key_name, algorithm, key_size, encrypted)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                key_name,
                algorithm,
                key_size,
                1 if encrypted else 0
            ))
            self.conn.commit()
    
    def log_error(self, message: str, details: Dict = None):
        """
        Log an error.
        
        Args:
            message: Error message
            details: Additional details
        """
        self.stats['errors'] += 1
        self.file_logger.error(message)
        
        if self.db_enabled:
            self.cursor.execute('''
                INSERT INTO operations (timestamp, operation_type, success,
                                       error_message, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                'error',
                0,
                message,
                json.dumps(details) if details else None
            ))
            self.conn.commit()
    
    # ==================== Query Operations ====================
    
    def get_operations(self, limit: int = 100, operation_type: str = None) -> List[Dict]:
        """
        Get operation history.
        
        Args:
            limit: Maximum number of results
            operation_type: Filter by operation type
            
        Returns:
            List of operation dictionaries
        """
        if not self.db_enabled:
            return []
        
        query = "SELECT * FROM operations"
        params = []
        
        if operation_type:
            query += " WHERE operation_type = ?"
            params.append(operation_type)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        self.cursor.execute(query, params)
        columns = [description[0] for description in self.cursor.description]
        
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]
    
    def get_keys(self) -> List[Dict]:
        """
        Get list of generated keys.
        
        Returns:
            List of key dictionaries
        """
        if not self.db_enabled:
            return []
        
        self.cursor.execute("SELECT * FROM keys ORDER BY timestamp DESC")
        columns = [description[0] for description in self.cursor.description]
        
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]
    
    def get_statistics(self) -> Dict:
        """Get logging statistics."""
        return {
            **self.stats,
            'uptime': str(datetime.now() - self.stats['start_time'])
        }
    
    # ==================== Display Methods ====================
    
    def print_banner(self):
        """Print the application banner."""
        banner = f"""
{Color.CYAN}{Color.BOLD}
======================================================================
                      CryptoGuard - Version 1.0.0
              Encryption / Decryption Tool
======================================================================
  For authorized use only.
  Always keep your encryption keys safe.
======================================================================
{Color.RESET}
"""
        print(banner)
    
    def print_legal_notice(self):
        """Print legal notice."""
        notice = f"""
{Color.YELLOW}{Color.BOLD}
======================================================================
                         LEGAL NOTICE
======================================================================
  Use encryption ethically and responsibly.

  - Always keep your encryption keys safe
  - Losing the key means you CANNOT decrypt your data
  - Unauthorized encryption of others' data is illegal
  - Use for protecting YOUR OWN data only
======================================================================
{Color.RESET}
"""
        print(notice)
    
    def print_success(self, message: str):
        """Print success message."""
        print(f"{Color.GREEN}[OK] {message}{Color.RESET}")
    
    def print_error(self, message: str):
        """Print error message."""
        print(f"{Color.RED}[ERROR] {message}{Color.RESET}")
    
    def print_info(self, message: str):
        """Print info message."""
        print(f"{Color.CYAN}[INFO] {message}{Color.RESET}")
    
    def print_warning(self, message: str):
        """Print warning message."""
        print(f"{Color.YELLOW}[WARN] {message}{Color.RESET}")
    
    def print_statistics(self):
        """Print current statistics."""
        stats = self.get_statistics()
        
        print(f"\n{Color.CYAN}{'='*50}{Color.RESET}")
        print(f"{Color.CYAN}  STATISTICS{Color.RESET}")
        print(f"{Color.CYAN}{'='*50}{Color.RESET}")
        print(f"  Total Operations: {stats['operations']}")
        print(f"  Encryptions: {stats['encryptions']}")
        print(f"  Decryptions: {stats['decryptions']}")
        print(f"  Key Generations: {stats['key_generations']}")
        print(f"  Errors: {stats['errors']}")
        print(f"  Uptime: {stats['uptime']}")
        print(f"{Color.CYAN}{'='*50}{Color.RESET}\n")
    
    def close(self):
        """Close database connection."""
        if self.db_enabled:
            self.conn.close()
