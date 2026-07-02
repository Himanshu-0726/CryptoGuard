"""
Utility Functions Module
========================

Helper functions for clipboard, validation, and file operations.
"""

import os
import re
import string
import secrets
import shutil
from pathlib import Path
from typing import Optional, Tuple


def copy_to_clipboard(text: str) -> bool:
    """
    Copy text to clipboard.
    
    Args:
        text: Text to copy
        
    Returns:
        True if successful
    """
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except Exception:
        return False


def paste_from_clipboard() -> Optional[str]:
    """
    Get text from clipboard.
    
    Returns:
        Clipboard text or None
    """
    try:
        import pyperclip
        return pyperclip.paste()
    except Exception:
        return None


def clear_clipboard() -> bool:
    """Clear the clipboard."""
    try:
        import pyperclip
        pyperclip.copy('')
        return True
    except Exception:
        return False


def validate_password(password: str, min_length: int = 8) -> Tuple[bool, str]:
    """
    Validate password strength.
    
    Args:
        password: Password to validate
        min_length: Minimum password length
        
    Returns:
        Tuple of (is_valid, message)
    """
    if len(password) < min_length:
        return False, f"Password must be at least {min_length} characters"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    score = sum([has_upper, has_lower, has_digit, has_special])
    
    if score < 2:
        return False, "Password must contain at least 2 of: uppercase, lowercase, digit, special character"
    
    return True, "Password is valid"


def calculate_password_strength(password: str) -> Tuple[int, str]:
    """
    Calculate password strength score.
    
    Args:
        password: Password to evaluate
        
    Returns:
        Tuple of (score, label)
    """
    score = 0
    
    # Length score
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1
    
    # Character variety
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 1
    
    # Normalize to 0-4 scale
    score = min(4, score // 2)
    
    labels = {
        0: "Very Weak",
        1: "Weak",
        2: "Fair",
        3: "Strong",
        4: "Very Strong"
    }
    
    return score, labels.get(score, "Unknown")


def generate_random_string(length: int = 32) -> str:
    """
    Generate a secure random string.
    
    Args:
        length: Length of the string
        
    Returns:
        Random string
    """
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def secure_delete_file(file_path: str) -> bool:
    """
    Securely delete a file by overwriting before deletion.
    
    Args:
        file_path: Path to file to delete
        
    Returns:
        True if successful
    """
    try:
        path = Path(file_path)
        if not path.exists():
            return True
        
        # Get file size
        file_size = path.stat().st_size
        
        # Overwrite with random data
        with open(path, 'wb') as f:
            f.write(secrets.token_bytes(file_size))
        
        # Overwrite with zeros
        with open(path, 'wb') as f:
            f.write(b'\x00' * file_size)
        
        # Delete the file
        path.unlink()
        
        return True
    except Exception:
        return False


def ensure_directory(dir_path: str) -> bool:
    """
    Ensure a directory exists.
    
    Args:
        dir_path: Path to directory
        
    Returns:
        True if directory exists or was created
    """
    try:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        return True
    except Exception:
        return False


def get_file_size(file_path: str) -> Optional[int]:
    """
    Get file size in bytes.
    
    Args:
        file_path: Path to file
        
    Returns:
        File size in bytes or None
    """
    try:
        return os.path.getsize(file_path)
    except Exception:
        return None


def format_file_size(size_bytes: int) -> str:
    """
    Format file size to human readable string.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted string
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing invalid characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    return filename


def is_valid_email(email: str) -> bool:
    """
    Validate email format.
    
    Args:
        email: Email address to validate
        
    Returns:
        True if valid
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def get_timestamp() -> str:
    """
    Get current timestamp as formatted string.
    
    Returns:
        Timestamp string (YYYY-MM-DD HH:MM:SS)
    """
    from datetime import datetime
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def truncate_string(text: str, max_length: int = 50) -> str:
    """
    Truncate a string with ellipsis.
    
    Args:
        text: Original string
        max_length: Maximum length
        
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."


def calculate_hash(data: bytes, algorithm: str = 'sha256') -> str:
    """
    Calculate hash of data.
    
    Args:
        data: Data to hash
        algorithm: Hash algorithm
        
    Returns:
        Hex digest string
    """
    import hashlib
    
    if algorithm == 'md5':
        return hashlib.md5(data).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(data).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(data).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(data).hexdigest()
    else:
        return hashlib.sha256(data).hexdigest()
