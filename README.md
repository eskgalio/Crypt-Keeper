# 🦇 The Crypt Keeper

*"Where passwords go to rest... eternally!"*

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-AES--256-red.svg)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

## 🪦 Overview

The Crypt Keeper is a powerful, local-first secrets management tool designed for development and IT teams. It automatically detects, encrypts, and rotates secrets in configuration files - all without requiring any cloud services. With its unique Gothic horror theme, it makes security management both effective and entertaining.

## ⚰️ Key Features

- **🔍 Secrets Hunter**: 
  - Scans local files for exposed passwords and API keys
  - Uses advanced regex patterns for detection
  - Supports multiple secret types (AWS keys, database passwords, API tokens)
  - Provides masked preview of detected secrets

- **🔐 One-Click Encryption**:
  - AES-256 encryption for all secrets
  - Automatic backup before modifications
  - YAML-aware processing
  - Safe file handling with UTF-8 support

- **🎲 Password Generator**:
  - Secure random password generation
  - Multiple formats (random, memorable, API keys)
  - Follows NIST security guidelines
  - Gothic-themed memorable passwords

- **📜 Graveyard Mode**:
  - Detailed audit logging of all operations
  - Spooky Gothic messages for each action
  - Timestamp and location tracking
  - File-specific history viewing

- **🔑 Emergency Recovery**:
  - Master key system for secret recovery
  - Automatic backup creation
  - Safe error handling and rollback
  - Local-only storage for maximum security

## 🕯️ Requirements

- Python 3.8 or higher
- Operating Systems: Windows, Linux, macOS
- No external services required

## 🧛‍♂️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cryptkeeper.git
cd cryptkeeper

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## 🦇 Usage

### Scanning for Secrets
```bash
# Scan current directory
cryptkeeper scan .

# Scan specific directory with exclusions
cryptkeeper scan /path/to/dir --exclude "*.pyc" "venv/*"
```

### Encrypting Secrets
```bash
# Encrypt secrets in a file
cryptkeeper encrypt config.yml

# Encrypt without backup
cryptkeeper encrypt config.yml --no-backup
```

### Decrypting Secrets
```bash
# Decrypt secrets in a file
cryptkeeper decrypt config.yml

# View decryption history
cryptkeeper history --file config.yml
```

### Generating Secrets
```bash
# Generate memorable password
cryptkeeper generate --type memorable

# Generate random password
cryptkeeper generate --type password --length 20

# Generate multiple API keys
cryptkeeper generate --type api-key --count 5
```

### Viewing History
```bash
# View all operations
cryptkeeper history

# View last 30 days of history
cryptkeeper history --days 30
```

## 🔮 Security Features

- **Encryption**: AES-256 encryption using the cryptography library
- **Key Management**: Secure master key generation and storage
- **Backups**: Automatic backup creation before modifications
- **Audit Trail**: Comprehensive logging of all operations
- **Local Storage**: No cloud dependencies or external services
- **Safe Handling**: UTF-8 encoding and proper file handling

## ⚠️ Best Practices

1. **Master Key**:
   - Keep a secure backup of your master key
   - Store the key separate from encrypted files
   - Rotate master key periodically

2. **Backups**:
   - Don't disable automatic backups unless necessary
   - Keep backup files in a secure location
   - Verify backups regularly

3. **Usage**:
   - Scan files before encryption
   - Review changes before applying
   - Monitor audit logs regularly

## 🪦 Directory Structure

```
cryptkeeper/
├── cryptkeeper/
│   ├── __init__.py
│   ├── cli.py          # Command-line interface
│   ├── crypto.py       # Encryption/decryption logic
│   ├── generator.py    # Password generation
│   ├── graveyard.py   # Audit logging
│   └── hunter.py       # Secret detection
├── requirements.txt
├── setup.py
└── README.md
```

## 🦇 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 🎭 Acknowledgments

- Inspired by the classic horror host "The Crypt Keeper"
- Built with security and privacy in mind
- Gothic horror theme makes security fun

---

*"Sleep well, your secrets are safe in their crypts..."* 🦇 
