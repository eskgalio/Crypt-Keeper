"""
Crypto - Handles encryption and decryption of secrets using AES-256.
"""

import base64
import os
from typing import Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path
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
logger = logging.getLogger("crypto")

class CryptKeeper:
    """Handles encryption and decryption of secrets."""
    
    def __init__(self, master_key_file: Path = None):
        """
        Initialize the CryptKeeper with a master key.
        
        Args:
            master_key_file: Path to the master key file. If None, a new one will be generated.
        """
        self.master_key_file = master_key_file or Path.home() / '.cryptkeeper' / 'master.key'
        self.master_key = self._load_or_create_master_key()
        self.fernet = Fernet(self.master_key)
        
    def _load_or_create_master_key(self) -> bytes:
        """Load existing master key or create a new one."""
        if self.master_key_file.exists():
            logger.info("🔑 Loading existing master key...")
            return self.master_key_file.read_bytes()
        
        # Create new master key
        logger.info("🦇 Generating new master key...")
        key = Fernet.generate_key()
        
        # Ensure directory exists
        self.master_key_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Save the key
        self.master_key_file.write_bytes(key)
        logger.info(f"💀 Master key saved to {self.master_key_file}")
        
        return key
    
    def derive_key(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        Derive an encryption key from a password using PBKDF2.
        
        Args:
            password: The password to derive the key from
            salt: Optional salt bytes. If None, generates new salt.
            
        Returns:
            Tuple of (key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def encrypt(self, data: str) -> str:
        """
        Encrypt a string using the master key.
        
        Args:
            data: String to encrypt
            
        Returns:
            Encrypted string in base64 format
        """
        try:
            encrypted = self.fernet.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"💀 Encryption failed: {str(e)}")
            raise
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt an encrypted string using the master key.
        
        Args:
            encrypted_data: Base64 encoded encrypted string
            
        Returns:
            Decrypted string
        """
        try:
            decoded = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.fernet.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"💀 Decryption failed: {str(e)}")
            raise
    
    def rotate_key(self) -> None:
        """Generate a new master key and re-encrypt all secrets."""
        # TODO: Implement key rotation logic
        # This would involve:
        # 1. Generate new master key
        # 2. Decrypt all secrets with old key
        # 3. Re-encrypt all secrets with new key
        # 4. Update master key file
        pass 