"""
CLI - Command line interface for The Crypt Keeper.
"""

import typer
from pathlib import Path
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from datetime import datetime, timedelta
import yaml
import re

from .hunter import SecretsHunter
from .crypto import CryptKeeper
from .generator import PasswordGenerator
from .graveyard import Graveyard, Tombstone

app = typer.Typer(
    name="cryptkeeper",
    help="🦇 The Crypt Keeper - Automated Secrets Vault & Password Rotator",
    add_completion=False
)
console = Console()

@app.command()
def scan(
    directory: Path = typer.Argument(
        ...,
        help="Directory to scan for secrets",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True
    ),
    exclude: List[str] = typer.Option(
        None,
        help="Glob patterns to exclude from scan"
    )
):
    """Scan for secrets in files."""
    console.print("🦇 [bold red]The Crypt Keeper rises...[/bold red]")
    
    hunter = SecretsHunter()
    findings = hunter.scan_directory(directory, exclude)
    
    if not findings:
        console.print("\n[green]No secrets found! Your codebase is clean... for now.[/green] 👻")
        return
        
    table = Table(title="🔍 Discovered Secrets")
    table.add_column("File", style="cyan")
    table.add_column("Line", style="magenta")
    table.add_column("Type", style="red")
    table.add_column("Secret", style="yellow")
    
    for finding in findings:
        # Mask the secret value for display
        secret = finding['match']
        masked = secret[:4] + '*' * (len(secret) - 4)
        table.add_row(
            finding['file'],
            str(finding['line']),
            finding['pattern'],
            masked
        )
        
    console.print(table)
    console.print("\n[yellow]Use 'cryptkeeper encrypt' to secure these secrets![/yellow]")

@app.command()
def encrypt(
    file_path: Path = typer.Argument(
        ...,
        help="File containing secrets to encrypt",
        exists=True,
        file_okay=True,
        dir_okay=False,
        resolve_path=True
    ),
    backup: bool = typer.Option(
        True,
        help="Create a backup of the original file"
    )
):
    """Encrypt secrets in a file."""
    console.print("🔐 [bold red]Preparing to lay these secrets to rest...[/bold red]")
    
    crypto = CryptKeeper()
    graveyard = Graveyard()
    
    # Create backup if requested
    if backup:
        backup_path = file_path.with_suffix(file_path.suffix + '.bak')
        import shutil
        shutil.copy2(file_path, backup_path)
        console.print(f"[green]Created backup at {backup_path}[/green]")
    
    try:
        # Read the file content
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse YAML if it's a YAML file
        if file_path.suffix.lower() in ['.yml', '.yaml']:
            try:
                yaml.safe_load(content)
            except yaml.YAMLError as e:
                console.print(f"[red]Warning: Invalid YAML format - {str(e)}[/red]")
        
        # Find secrets
        hunter = SecretsHunter()
        findings = hunter.scan_file(file_path)
        
        if not findings:
            console.print("[green]No secrets found in this file.[/green]")
            return
        
        # Sort findings by position in reverse order to avoid offset issues
        findings.sort(key=lambda x: (-x['line'], -x['start']))
        
        # Track changes for verification
        changes_made = 0
        
        # Encrypt each secret
        for finding in findings:
            secret = finding['match']
            encrypted = crypto.encrypt(secret)
            encrypted_value = f"CRYPT_{encrypted}"
            
            # Create a tombstone
            tombstone = Tombstone(
                action="encrypt",
                file_path=str(file_path),
                secret_type=finding['pattern'],
                details={
                    'line': finding['line'],
                    'original_length': len(secret)
                }
            )
            graveyard.add_tombstone(tombstone)
            
            # Replace in content
            new_content = content.replace(secret, encrypted_value)
            if new_content != content:
                content = new_content
                changes_made += 1
                console.print(f"[green]Encrypted {finding['pattern']} on line {finding['line']}[/green]")
        
        # Save the file only if changes were made
        if changes_made > 0:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            console.print(f"[green]✨ {changes_made} secrets have been laid to rest![/green]")
        else:
            console.print("[yellow]No changes were made to the file.[/yellow]")
            
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        if backup:
            console.print("[yellow]Restoring from backup...[/yellow]")
            shutil.copy2(backup_path, file_path)
            console.print("[green]File restored from backup.[/green]")

@app.command()
def decrypt(
    file_path: Path = typer.Argument(
        ...,
        help="File containing encrypted secrets",
        exists=True,
        file_okay=True,
        dir_okay=False,
        resolve_path=True
    ),
    backup: bool = typer.Option(
        True,
        help="Create a backup of the encrypted file"
    )
):
    """Decrypt secrets in a file."""
    console.print("👻 [bold red]Summoning secrets from beyond...[/bold red]")
    
    crypto = CryptKeeper()
    graveyard = Graveyard()
    
    # Create backup if requested
    if backup:
        backup_path = file_path.with_suffix(file_path.suffix + '.encrypted')
        import shutil
        shutil.copy2(file_path, backup_path)
        console.print(f"[green]Created backup at {backup_path}[/green]")
    
    try:
        # Read the file
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find encrypted secrets
        encrypted_pattern = r'CRYPT_([A-Za-z0-9+/=_-]+)'
        matches = list(re.finditer(encrypted_pattern, content))
        
        if not matches:
            console.print("[yellow]No encrypted secrets found in this file.[/yellow]")
            return
        
        # Sort matches in reverse order to avoid offset issues
        matches.sort(key=lambda m: -m.start())
        
        # Track changes
        changes_made = 0
        
        # Decrypt each secret
        for match in matches:
            encrypted = match.group(1)
            try:
                decrypted_value = crypto.decrypt(encrypted)
                
                # Create a tombstone
                tombstone = Tombstone(
                    action="decrypt",
                    file_path=str(file_path),
                    secret_type="encrypted_value",
                    details={'position': match.start()}
                )
                graveyard.add_tombstone(tombstone)
                
                # Replace in content
                content = content.replace(f"CRYPT_{encrypted}", decrypted_value)
                changes_made += 1
                
            except Exception as e:
                console.print(f"[red]Failed to decrypt a secret: {str(e)}[/red]")
        
        # Save the file only if changes were made
        if changes_made > 0:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            console.print(f"[green]🌟 {changes_made} secrets have risen from their graves![/green]")
        else:
            console.print("[yellow]No changes were made to the file.[/yellow]")
            
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        if backup:
            console.print("[yellow]Restoring from backup...[/yellow]")
            shutil.copy2(backup_path, file_path)
            console.print("[green]File restored from backup.[/green]")

@app.command()
def generate(
    type: str = typer.Option(
        "password",
        help="Type of secret to generate (password/api-key/memorable)"
    ),
    length: int = typer.Option(
        16,
        help="Length of the generated secret"
    ),
    count: int = typer.Option(
        1,
        help="Number of secrets to generate"
    )
):
    """Generate new secrets."""
    console.print("🎭 [bold red]Conjuring new secrets...[/bold red]")
    
    generator = PasswordGenerator()
    
    table = Table(title="🔮 Generated Secrets")
    table.add_column("Type", style="cyan")
    table.add_column("Value", style="magenta")
    
    try:
        for _ in range(count):
            if type == "password":
                value = generator.generate_password(length)
            elif type == "api-key":
                value = generator.generate_api_key(length=length)
            elif type == "memorable":
                value = generator.generate_memorable_password()
            else:
                console.print(f"[red]Unknown secret type: {type}[/red]")
                return
                
            table.add_row(type, value)
            
        console.print(table)
    except Exception as e:
        console.print(f"[red]Error generating secret: {str(e)}[/red]")

@app.command()
def history(
    days: int = typer.Option(
        7,
        help="Number of days of history to show"
    ),
    file_path: Optional[Path] = typer.Option(
        None,
        help="Show history for specific file",
        exists=True,
        file_okay=True,
        dir_okay=False
    )
):
    """View the audit history."""
    console.print("📜 [bold red]Opening the ancient scrolls...[/bold red]")
    
    graveyard = Graveyard()
    
    start_date = datetime.now() - timedelta(days=days)
    
    if file_path:
        tombstones = graveyard.get_file_history(str(file_path))
    else:
        tombstones = graveyard.get_tombstones(start_date=start_date)
        
    if not tombstones:
        console.print("[yellow]The graveyard is empty... for now.[/yellow]")
        return
        
    table = Table(title="⚰️ Secret History")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Action", style="red")
    table.add_column("File", style="magenta")
    table.add_column("Type", style="green")
    table.add_column("Details", style="yellow")
    
    for stone in sorted(tombstones, key=lambda x: x.timestamp, reverse=True):
        details = stone.details.get('line', '')
        if details:
            details = f"Line {details}"
            
        table.add_row(
            stone.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            stone.action,
            stone.file_path,
            stone.secret_type,
            details
        )
        
    console.print(table)

def main():
    """Entry point for the CLI."""
    app() 