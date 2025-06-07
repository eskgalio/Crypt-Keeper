"""
Secrets Hunter - Scans files for potential secrets and sensitive information.
"""

import re
from pathlib import Path
from typing import Dict, List, Pattern
import logging
from rich.console import Console
from rich.logging import RichHandler

# Configure rich logging
console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
logger = logging.getLogger("hunter")

# Common secret patterns
SECRET_PATTERNS: Dict[str, Pattern] = {
    'aws_access_key': re.compile(r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])'),
    'aws_secret_key': re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'),
    'password_field': re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"](.*?)[\'"]'),
    'api_key': re.compile(r'(?i)(api[_-]?key|apikey|token)\s*[=:]\s*[\'"](.*?)[\'"]'),
    'private_key': re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
    'connection_string': re.compile(r'(?i)(mongodb|postgresql|mysql)://[^\s<>"\']+'),
}

class SecretsHunter:
    def __init__(self, patterns: Dict[str, Pattern] = None):
        """Initialize the Secrets Hunter with optional custom patterns."""
        self.patterns = patterns or SECRET_PATTERNS
        
    def scan_file(self, file_path: Path) -> List[Dict]:
        """
        Scan a single file for potential secrets.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            List of dictionaries containing found secrets with their locations
        """
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.readlines()
                
            for line_num, line in enumerate(content, 1):
                for pattern_name, pattern in self.patterns.items():
                    matches = pattern.finditer(line)
                    for match in matches:
                        finding = {
                            'file': str(file_path),
                            'line': line_num,
                            'pattern': pattern_name,
                            'match': match.group(0),
                            'start': match.start(),
                            'end': match.end()
                        }
                        findings.append(finding)
                        logger.warning(f"🦇 [red]Found potential {pattern_name} in {file_path}::{line_num}[/red]")
                        
        except Exception as e:
            logger.error(f"💀 Failed to scan {file_path}: {str(e)}")
            
        return findings
    
    def scan_directory(self, directory: Path, exclude_patterns: List[str] = None) -> List[Dict]:
        """
        Recursively scan a directory for secrets.
        
        Args:
            directory: Path to the directory to scan
            exclude_patterns: List of glob patterns to exclude
            
        Returns:
            List of all findings across all files
        """
        if exclude_patterns is None:
            exclude_patterns = ['**/venv/*', '**/.git/*', '**/__pycache__/*', '**/*.pyc']
            
        all_findings = []
        
        try:
            for file_path in directory.rglob('*'):
                # Skip if file matches any exclude pattern
                if any(file_path.match(pattern) for pattern in exclude_patterns):
                    continue
                    
                # Only scan text files
                if file_path.is_file() and self._is_text_file(file_path):
                    findings = self.scan_file(file_path)
                    all_findings.extend(findings)
                    
        except Exception as e:
            logger.error(f"💀 Failed to scan directory {directory}: {str(e)}")
            
        return all_findings
    
    @staticmethod
    def _is_text_file(file_path: Path) -> bool:
        """Check if a file is likely to be a text file based on extension."""
        text_extensions = {
            '.txt', '.py', '.js', '.json', '.yml', '.yaml', '.env',
            '.ini', '.cfg', '.conf', '.xml', '.md', '.sh', '.bash',
            '.properties', '.toml', '.csv'
        }
        return file_path.suffix.lower() in text_extensions 