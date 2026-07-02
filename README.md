# CryptoGuard

Encryption / Decryption Tool for Secure Text and File Protection

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## ⚠️ Important Warning

**Always keep your encryption keys safe. Losing the key means you CANNOT decrypt your data.**

---

## What is CryptoGuard?

CryptoGuard is a comprehensive encryption tool that protects your sensitive data using industry-standard cryptographic algorithms.

### Features

- **AES-256 Encryption** - Industry-standard symmetric encryption
- **Fernet Encryption** - Simple, secure encryption
- **RSA Encryption** - Asymmetric encryption for key exchange
- **Key Management** - Generate, store, and manage encryption keys
- **File Encryption** - Encrypt any file type
- **Text Encryption** - Encrypt text messages
- **GUI Interface** - User-friendly graphical interface
- **CLI Interface** - Command-line interface for power users

---

## ⚠️ Key Safety Warning

### Losing Your Key = Losing Your Data

- There is **NO key recovery mechanism**
- There is **NO backdoor**
- The developers **CANNOT** help you recover lost keys
- **Always create backups** of your encryption keys

### Best Practices

1. Store keys in a password manager
2. Create encrypted backups of keys
3. Use strong passwords to protect keys
4. Test decryption before deleting originals
5. Never share keys with untrusted parties

---

## Installation

### Prerequisites

- Python 3.8 or higher

### Steps

1. **Clone or download the project:**
   ```bash
   cd CryptoGuard
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation:**
   ```bash
   python encryptor.py --accept-terms --list-algorithms
   ```

---

## Usage

### CLI Interface

**Encrypt text:**
```bash
python encryptor.py --accept-terms --encrypt "Hello World" --password mypass
```

**Decrypt text:**
```bash
python encryptor.py --accept-terms --decrypt "encrypted_text" --password mypass
```

**Encrypt file:**
```bash
python encryptor.py --accept-terms --encrypt-file document.txt --password mypass
```

**Decrypt file:**
```bash
python encryptor.py --accept-terms --decrypt-file document.txt.enc --password mypass
```

**Generate key:**
```bash
python encryptor.py --accept-terms --generate-key mykey --algorithm aes
```

**List keys:**
```bash
python encryptor.py --accept-terms --list-keys
```

**Launch GUI:**
```bash
python encryptor.py --accept-terms --gui
```

### GUI Interface

Launch the graphical interface:
```bash
python gui.py
```

The GUI provides:
- **Text Encryption Tab** - Encrypt/decrypt text
- **File Encryption Tab** - Encrypt/decrypt files
- **Key Management Tab** - Generate/view keys
- **Settings Tab** - Configure options

---

## Command Line Options

| Option | Description |
|--------|-------------|
| `--accept-terms` | Accept legal terms (required) |
| `--gui` | Launch GUI interface |
| `--encrypt TEXT` | Encrypt text |
| `--decrypt TEXT` | Decrypt text |
| `--encrypt-file FILE` | Encrypt a file |
| `--decrypt-file FILE` | Decrypt a file |
| `--algorithm ALG` | Algorithm (aes, fernet, rsa) |
| `--password PASS` | Encryption password |
| `--generate-key NAME` | Generate a key |
| `--list-keys` | List stored keys |
| `--list-algorithms` | List algorithms |
| `--output FILE` | Output file |
| `--clipboard` | Copy result to clipboard |

---

## Supported Algorithms

| Algorithm | Type | Use Case |
|-----------|------|----------|
| **AES-256-CBC** | Symmetric | Fast encryption of large data |
| **Fernet** | Symmetric | Simple, secure encryption |
| **RSA-2048** | Asymmetric | Key exchange, small data |

---

## Configuration

Edit `config.yaml` to customize behavior:

```yaml
# Encryption Settings
encryption:
  default_algorithm: "aes"
  aes_key_size: 256
  rsa_key_size: 2048
  pbkdf2_iterations: 100000

# File Settings
files:
  keys_dir: "keys"
  encrypted_dir: "encrypted"
  encrypted_extension: ".enc"

# Logging Settings
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
├── encryptor.py              # CLI interface
├── gui.py                    # GUI interface
├── requirements.txt          # Dependencies
├── config.yaml               # Configuration
├── LICENSE                   # MIT License
├── DISCLAIMER.md             # Legal notice
├── README.md                 # Documentation
├── modules/
│   ├── __init__.py
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

## Ethical Use Guidelines

This tool is designed for protecting YOUR OWN data:

1. **Personal Data Protection**
   - Encrypt passwords and credentials
   - Protect sensitive documents
   - Secure personal notes

2. **Educational Purposes**
   - Learn about cryptography
   - Understand encryption algorithms
   - Practice secure key management

3. **Secure Communication**
   - Encrypt messages for trusted parties
   - Share sensitive information securely
   - Protect confidential data

---

## Security Features

- **AES-256** - Industry-standard encryption
- **PBKDF2** - Secure key derivation
- **Secure Random** - Cryptographically secure random number generation
- **PKCS7 Padding** - Proper data padding
- **Key Encryption** - Keys can be encrypted with passwords

---

## Troubleshooting

**"Password too short" error:**
```bash
# Use a stronger password (8+ characters with mixed case, numbers, symbols)
```

**"Decryption failed" error:**
```bash
# Check that you're using the correct password and algorithm
```

**"Key not found" error:**
```bash
# List available keys
python encryptor.py --accept-terms --list-keys
```

---

## License

This project is licensed under the MIT License with Ethical Use Clause.

See [LICENSE](LICENSE) for details.

---

## Disclaimer

Use encryption ethically and responsibly. Always keep your encryption keys safe. See [DISCLAIMER.md](DISCLAIMER.md) for full details.

---

**Remember: Always keep your encryption keys safe! Losing the key means you CANNOT decrypt your data.**
