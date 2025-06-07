"""
Generator - Creates secure passwords and API keys.
"""

import secrets
import string
from typing import List
import logging
from rich.logging import RichHandler
from rich.console import Console

# Configure rich logging
console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
logger = logging.getLogger("generator")

class PasswordGenerator:
    """Generates secure passwords and API keys."""
    
    def __init__(self):
        self.char_sets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'special': '!@#$%^&*()_+-=[]{}|;:,.<>?'
        }
    
    def generate_password(self, length: int = 16, include_sets: List[str] = None) -> str:
        """
        Generate a secure password.
        
        Args:
            length: Length of the password
            include_sets: List of character sets to include
            
        Returns:
            Generated password
        """
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")
            
        if include_sets is None:
            include_sets = ['lowercase', 'uppercase', 'digits', 'special']
            
        # Validate character sets
        for char_set in include_sets:
            if char_set not in self.char_sets:
                raise ValueError(f"Invalid character set: {char_set}")
        
        # Create character pool
        char_pool = ''.join(self.char_sets[char_set] for char_set in include_sets)
        
        # Ensure at least one character from each set
        password = [
            secrets.choice(self.char_sets[char_set])
            for char_set in include_sets
        ]
        
        # Fill remaining length with random characters
        remaining_length = length - len(password)
        password.extend(secrets.choice(char_pool) for _ in range(remaining_length))
        
        # Shuffle the password
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        
        return ''.join(password_list)
    
    def generate_api_key(self, prefix: str = None, length: int = 32) -> str:
        """
        Generate a secure API key.
        
        Args:
            prefix: Optional prefix for the API key
            length: Length of the key (not including prefix)
            
        Returns:
            Generated API key
        """
        if length < 16:
            raise ValueError("API key length must be at least 16 characters")
            
        # Generate random bytes and encode as base32
        random_bytes = secrets.token_bytes(length)
        key = secrets.token_urlsafe(length)
        
        # Add prefix if specified
        if prefix:
            key = f"{prefix}_{key}"
            
        return key
    
    def generate_uuid(self) -> str:
        """Generate a UUID v4."""
        return secrets.token_hex(16)
    
    def generate_salt(self, length: int = 16) -> bytes:
        """Generate random salt bytes."""
        return secrets.token_bytes(length)
    
    def generate_memorable_password(self, num_words: int = 4) -> str:
        """
        Generate a memorable password using words.
        
        Args:
            num_words: Number of words to use
            
        Returns:
            Generated memorable password
        """
        # List of common but memorable words
        words = [
            "castle", "crypt", "ghost", "grave", "witch", "spell",
            "magic", "dark", "night", "moon", "star", "blood",
            "bone", "skull", "tomb", "death", "black", "crow",
            "raven", "wolf", "bat", "owl", "cat", "spider"
        ]
        
        # Select random words
        selected_words = [secrets.choice(words) for _ in range(num_words)]
        
        # Add some random digits
        digits = ''.join(secrets.choice(string.digits) for _ in range(2))
        
        # Add a special character
        special = secrets.choice('!@#$%^&*')
        
        return f"{'-'.join(selected_words)}{special}{digits}" 