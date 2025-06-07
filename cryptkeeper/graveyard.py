"""
Graveyard - Audit logging system for tracking all changes to secrets.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.logging import RichHandler
from rich.console import Console

# Configure rich logging
console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
logger = logging.getLogger("graveyard")

class Tombstone:
    """Represents a single audit log entry."""
    
    def __init__(
        self,
        action: str,
        file_path: str,
        secret_type: str,
        timestamp: Optional[datetime] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        self.action = action
        self.file_path = file_path
        self.secret_type = secret_type
        self.timestamp = timestamp or datetime.utcnow()
        self.details = details or {}
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert the tombstone to a dictionary."""
        return {
            'action': self.action,
            'file_path': self.file_path,
            'secret_type': self.secret_type,
            'timestamp': self.timestamp.isoformat(),
            'details': self.details
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Tombstone':
        """Create a Tombstone from a dictionary."""
        return cls(
            action=data['action'],
            file_path=data['file_path'],
            secret_type=data['secret_type'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            details=data['details']
        )
        
    def __str__(self) -> str:
        """Return a spooky string representation."""
        messages = {
            'encrypt': "A new secret was laid to rest... 🦇",
            'decrypt': "A secret rises from its grave! 👻",
            'rotate': "The old password's soul has been reborn... ⚰️",
            'delete': "Another secret joins the eternal slumber... 💀"
        }
        return f"{messages.get(self.action, '🪦')} [{self.timestamp}] {self.file_path}"

class Graveyard:
    """Manages audit logging of all secret-related operations."""
    
    def __init__(self, log_dir: Path = None):
        """
        Initialize the Graveyard.
        
        Args:
            log_dir: Directory to store audit logs. Defaults to ~/.cryptkeeper/logs
        """
        self.log_dir = log_dir or Path.home() / '.cryptkeeper' / 'logs'
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.current_log = self.log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.json"
        
    def _load_tombstones(self) -> List[Tombstone]:
        """Load existing tombstones from the current log file."""
        if not self.current_log.exists():
            return []
            
        try:
            with open(self.current_log, 'r') as f:
                data = json.load(f)
                return [Tombstone.from_dict(item) for item in data]
        except Exception as e:
            logger.error(f"Failed to load audit log: {str(e)}")
            return []
            
    def _save_tombstones(self, tombstones: List[Tombstone]) -> None:
        """Save tombstones to the current log file."""
        try:
            with open(self.current_log, 'w') as f:
                json.dump([t.to_dict() for t in tombstones], f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save audit log: {str(e)}")
            
    def add_tombstone(self, tombstone: Tombstone) -> None:
        """Add a new tombstone to the graveyard."""
        tombstones = self._load_tombstones()
        tombstones.append(tombstone)
        self._save_tombstones(tombstones)
        logger.info(str(tombstone))
        
    def get_tombstones(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        action: Optional[str] = None,
        secret_type: Optional[str] = None
    ) -> List[Tombstone]:
        """
        Retrieve tombstones matching the given criteria.
        
        Args:
            start_date: Filter by start date
            end_date: Filter by end date
            action: Filter by action type
            secret_type: Filter by secret type
            
        Returns:
            List of matching tombstones
        """
        tombstones = self._load_tombstones()
        
        if start_date:
            tombstones = [t for t in tombstones if t.timestamp >= start_date]
        if end_date:
            tombstones = [t for t in tombstones if t.timestamp <= end_date]
        if action:
            tombstones = [t for t in tombstones if t.action == action]
        if secret_type:
            tombstones = [t for t in tombstones if t.secret_type == secret_type]
            
        return tombstones
    
    def get_file_history(self, file_path: str) -> List[Tombstone]:
        """Get the complete history for a specific file."""
        return [t for t in self._load_tombstones() if t.file_path == file_path]
    
    def get_latest_action(self, file_path: str) -> Optional[Tombstone]:
        """Get the most recent action for a file."""
        history = self.get_file_history(file_path)
        return max(history, key=lambda t: t.timestamp) if history else None 