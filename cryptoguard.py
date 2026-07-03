"""CryptoGuard - Simple Encryption Tool

Usage:
    python cryptoguard.py encrypt "Hello World"
    python cryptoguard.py decrypt "encrypted_text"
    python cryptoguard.py file-encrypt document.txt
    python cryptoguard.py file-decrypt document.txt.enc
    python cryptoguard.py keys
    python cryptoguard.py gui
"""

import os
import sys
import argparse
import getpass
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TERMS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".terms_accepted")


def check_terms():
    if os.path.exists(TERMS_FILE):
        return True
    print("\n" + "=" * 50)
    print("  LEGAL NOTICE")
    print("=" * 50)
    print("  Use encryption ethically and responsibly.")
    print("  - Always keep your encryption keys safe")
    print("  - Losing the key means you CANNOT decrypt your data")
    print("  - Unauthorized encryption of others' data is illegal")
    print("  - Use for protecting YOUR OWN data only")
    print("=" * 50)
    choice = input("\nAccept terms? (y/n): ").strip().lower()
    if choice == 'y':
        with open(TERMS_FILE, 'w') as f:
            f.write("accepted")
        return True
    print("Terms not accepted. Exiting.")
    return False


def get_password(prompt="Enter password: ", confirm=False):
    password = getpass.getpass(prompt)
    if confirm:
        password2 = getpass.getpass("Confirm password: ")
        if password != password2:
            print("Passwords don't match!")
            return None
    return password


def cmd_encrypt(args):
    from modules.crypto_engine import CryptoEngine
    from modules.logger import Logger

    password = args.password or get_password("Enter encryption password: ")
    if not password:
        return

    engine = CryptoEngine({})
    logger = Logger({})

    encrypted = engine.encrypt_text(args.text, password, args.algorithm, True)
    logger.print_success("Text encrypted successfully!")
    print(f"\nEncrypted text:\n{encrypted}\n")

    if args.output:
        with open(args.output, 'w') as f:
            f.write(encrypted)
        logger.print_success(f"Saved to {args.output}")


def cmd_decrypt(args):
    from modules.crypto_engine import CryptoEngine
    from modules.logger import Logger

    password = args.password or get_password("Enter decryption password: ")
    if not password:
        return

    engine = CryptoEngine({})
    logger = Logger({})

    try:
        decrypted = engine.decrypt_text(args.text, password, args.algorithm, True)
        logger.print_success("Text decrypted successfully!")
        print(f"\nDecrypted text:\n{decrypted}\n")

        if args.output:
            with open(args.output, 'w') as f:
                f.write(decrypted)
            logger.print_success(f"Saved to {args.output}")
    except Exception as e:
        logger.print_error(f"Decryption failed: {e}")
        print("Check your password and algorithm.")


def cmd_file_encrypt(args):
    from modules.key_manager import KeyManager
    from modules.file_handler import FileHandler
    from modules.logger import Logger

    password = args.password or get_password("Enter encryption password: ")
    if not password:
        return

    km = KeyManager({})
    fh = FileHandler({}, km)
    logger = Logger({})

    try:
        result = fh.encrypt_file(args.file, password, args.algorithm)
        logger.print_success("File encrypted successfully!")
        print(f"  Input: {result['input_file']}")
        print(f"  Output: {result['output_file']}")
        print(f"  Size: {result['original_size']:,} bytes")
    except Exception as e:
        logger.print_error(f"File encryption failed: {e}")


def cmd_file_decrypt(args):
    from modules.key_manager import KeyManager
    from modules.file_handler import FileHandler
    from modules.logger import Logger

    password = args.password or get_password("Enter decryption password: ")
    if not password:
        return

    km = KeyManager({})
    fh = FileHandler({}, km)
    logger = Logger({})

    try:
        result = fh.decrypt_file(args.file, password)
        logger.print_success("File decrypted successfully!")
        print(f"  Input: {result['input_file']}")
        print(f"  Output: {result['output_file']}")
    except Exception as e:
        logger.print_error(f"File decryption failed: {e}")


def cmd_keys(args):
    from modules.key_manager import KeyManager
    from modules.logger import Logger

    km = KeyManager({})
    logger = Logger({})
    keys = km.list_keys()

    if not keys:
        logger.print_info("No keys stored yet.")
        print("  Generate one with: python cryptoguard.py generate-key mykey")
        return

    print("\nStored Keys:")
    print("-" * 50)
    for key in keys:
        print(f"  {key['name']:<20} {key['algorithm'].upper():<10} {key['created_at'][:10]}")
    print("-" * 50 + "\n")


def cmd_generate_key(args):
    from modules.key_manager import KeyManager
    from modules.logger import Logger

    password = args.password or get_password("Enter password to encrypt key (or Enter for no encryption): ")
    if not password:
        password = None

    km = KeyManager({})
    logger = Logger({})

    try:
        if args.algorithm == 'aes':
            result = km.generate_aes_key(args.name, password, 256)
        elif args.algorithm == 'fernet':
            result = km.generate_fernet_key(args.name, password)
        elif args.algorithm == 'rsa':
            result = km.generate_rsa_keypair(args.name, password, 2048)
        logger.print_success(f"Key '{args.name}' generated!")
        print(f"  Algorithm: {result.get('algorithm', 'unknown')}")
    except Exception as e:
        logger.print_error(f"Key generation failed: {e}")


def cmd_gui(args):
    from gui import CryptoGuardGUI
    gui = CryptoGuardGUI({})
    gui.run()


def main():
    parser = argparse.ArgumentParser(
        description='CryptoGuard - Simple Encryption Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cryptoguard.py encrypt "Hello World"
  python cryptoguard.py decrypt "gAAAAABk..."
  python cryptoguard.py file-encrypt document.txt
  python cryptoguard.py file-decrypt document.txt.enc
  python cryptoguard.py keys
  python cryptoguard.py gui
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    enc = subparsers.add_parser('encrypt', help='Encrypt text')
    enc.add_argument('text', help='Text to encrypt')
    enc.add_argument('-p', '--password', help='Password (prompted if not provided)')
    enc.add_argument('-a', '--algorithm', default='aes', choices=['aes', 'fernet', 'rsa'])
    enc.add_argument('-o', '--output', help='Save to file')

    dec = subparsers.add_parser('decrypt', help='Decrypt text')
    dec.add_argument('text', help='Encrypted text')
    dec.add_argument('-p', '--password', help='Password')
    dec.add_argument('-a', '--algorithm', default='aes', choices=['aes', 'fernet', 'rsa'])
    dec.add_argument('-o', '--output', help='Save to file')

    fe = subparsers.add_parser('file-encrypt', help='Encrypt a file')
    fe.add_argument('file', help='File to encrypt')
    fe.add_argument('-p', '--password', help='Password')
    fe.add_argument('-a', '--algorithm', default='aes', choices=['aes', 'fernet', 'rsa'])

    fd = subparsers.add_parser('file-decrypt', help='Decrypt a file')
    fd.add_argument('file', help='Encrypted file')
    fd.add_argument('-p', '--password', help='Password')

    subparsers.add_parser('keys', help='List stored keys')

    gk = subparsers.add_parser('generate-key', help='Generate a new key')
    gk.add_argument('name', help='Key name')
    gk.add_argument('-a', '--algorithm', default='aes', choices=['aes', 'fernet', 'rsa'])
    gk.add_argument('-p', '--password', help='Password to encrypt key')

    subparsers.add_parser('gui', help='Launch GUI')

    subparsers.add_parser('algorithms', help='List algorithms')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if not check_terms():
        return

    if args.command == 'encrypt':
        cmd_encrypt(args)
    elif args.command == 'decrypt':
        cmd_decrypt(args)
    elif args.command == 'file-encrypt':
        cmd_file_encrypt(args)
    elif args.command == 'file-decrypt':
        cmd_file_decrypt(args)
    elif args.command == 'keys':
        cmd_keys(args)
    elif args.command == 'generate-key':
        cmd_generate_key(args)
    elif args.command == 'gui':
        cmd_gui(args)
    elif args.command == 'algorithms':
        from modules.crypto_engine import CryptoEngine
        engine = CryptoEngine({})
        algos = engine.get_available_algorithms()
        print("\nAlgorithms:")
        print("-" * 50)
        for name, desc in algos.items():
            print(f"  {name.upper():<10} {desc}")
        print("-" * 50 + "\n")


if __name__ == '__main__':
    main()
