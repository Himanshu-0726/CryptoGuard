# CryptoGuard

### Encryption / Decryption Tool for Secure Text and File Protection

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## Quick Start

```bash
git clone https://github.com/Himanshu-0726/CryptoGuard.git
cd CryptoGuard
pip install -r requirements.txt
python cryptoguard.py encrypt "Hello World"
```

---

## Usage

### Simple Commands

```bash
# Encrypt text
python cryptoguard.py encrypt "Hello World"

# Decrypt text
python cryptoguard.py decrypt "gAAAAABk...paste_here..."

# Encrypt a file
python cryptoguard.py file-encrypt document.txt

# Decrypt a file
python cryptoguard.py file-decrypt document.txt.enc

# List stored keys
python cryptoguard.py keys

# Generate a key
python cryptoguard.py generate-key mykey

# Launch GUI
python cryptoguard.py gui
```

### Password Options

```bash
# Pass password directly
python cryptoguard.py encrypt "Hello World" -p mypass

# Or use a different algorithm
python cryptoguard.py encrypt "Hello World" -a fernet

# Or save to file
python cryptoguard.py encrypt "Hello World" -o encrypted.txt
```

---

## Features

| Feature | Description |
|---------|-------------|
| AES-256 | Industry-standard symmetric encryption |
| Fernet | Simple, secure encryption |
| RSA-2048 | Asymmetric encryption for key exchange |
| Key Management | Generate, store, and manage encryption keys |
| File & Text Encryption | Protect any file or text message |
| GUI + CLI | Both graphical and command-line interfaces |

---

## Installation

**Prerequisites:** Python 3.8 or higher

```bash
git clone https://github.com/Himanshu-0726/CryptoGuard.git
cd CryptoGuard
pip install -r requirements.txt
```

Verify it works:
```bash
python encryptor.py --accept-terms --list-algorithms
```

---

## Usage

### CLI Examples

```bash
# Encrypt text
python encryptor.py --accept-terms --encrypt "Hello World" --password mypass

# Decrypt text
python encryptor.py --accept-terms --decrypt "encrypted_text" --password mypass

# Encrypt a file
python encryptor.py --accept-terms --encrypt-file document.txt --password mypass

# Decrypt a file
python encryptor.py --accept-terms --decrypt-file document.txt.enc --password mypass

# Generate a key
python encryptor.py --accept-terms --generate-key mykey --algorithm aes

# List stored keys
python encryptor.py --accept-terms --list-keys

# Launch GUI
python encryptor.py --accept-terms --gui
```

### GUI Interface

```bash
python gui.py
```

Tabs available: **Text Encryption** | **File Encryption** | **Key Management** | **Settings**

---

## CLI Options

| Command | Description |
|---------|-------------|
| `encrypt "text"` | Encrypt text |
| `decrypt "text"` | Decrypt text |
| `file-encrypt file.txt` | Encrypt a file |
| `file-decrypt file.txt.enc` | Decrypt a file |
| `keys` | List stored keys |
| `generate-key name` | Generate a new key |
| `gui` | Launch GUI |
| `algorithms` | List algorithms |

### Flags

| Flag | Description |
|------|-------------|
| `-p PASSWORD` | Password (prompted if not provided) |
| `-a ALGORITHM` | Algorithm: `aes`, `fernet`, `rsa` |
| `-o FILE` | Save output to file |

---

## Algorithms

| Algorithm | Type | Best For |
|-----------|------|----------|
| AES-256-CBC | Symmetric | Fast encryption of large data |
| Fernet | Symmetric | Simple, secure encryption |
| RSA-2048 | Asymmetric | Key exchange, small data |

---

## Configuration

Edit `config.yaml` to customize:

```yaml
encryption:
  default_algorithm: "aes"
  aes_key_size: 256
  rsa_key_size: 2048
  pbkdf2_iterations: 100000

files:
  keys_dir: "keys"
  encrypted_dir: "encrypted"
  encrypted_extension: ".enc"

logging:
  console: true
  file: true
  sqlite: true
  log_dir: "logs"
```

---

## Project Structure

```
CryptoGuard/
├── cryptoguard.py              # Simple CLI entry point (START HERE)
├── encryptor.py                # Advanced CLI interface
├── gui.py                      # GUI interface
├── requirements.txt          # Dependencies
├── config.yaml               # Configuration
├── LICENSE                   # MIT License
├── DISCLAIMER.md             # Legal notice
├── modules/
│   ├── crypto_engine.py      # Core encryption
│   ├── key_manager.py        # Key management
│   ├── file_handler.py       # File operations
│   ├── logger.py             # Logging
│   └── utils.py              # Utilities
├── keys/                     # Stored keys
├── encrypted/                # Encrypted files
└── logs/                     # Log files
```

---

## Troubleshooting

| Error | Solution |
|-------|----------|
| Password too short | Use 8+ characters with mixed case, numbers, symbols |
| Decryption failed | Check you're using the correct password and algorithm |
| Key not found | Run `python encryptor.py --accept-terms --list-keys` |

---

## License

MIT License with Ethical Use Clause. See [LICENSE](LICENSE) for details.

---

> **Remember:** Always keep your encryption keys safe! Losing the key means you **cannot** decrypt your data. There is no backdoor or recovery mechanism.
