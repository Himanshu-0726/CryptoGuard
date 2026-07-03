#!/usr/bin/env python3
"""
CryptoGuard GUI Interface
=========================

Graphical user interface for the CryptoGuard encryption tool.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from modules.crypto_engine import CryptoEngine
from modules.key_manager import KeyManager
from modules.file_handler import FileHandler
from modules.logger import Logger
from modules.utils import copy_to_clipboard, paste_from_clipboard, calculate_password_strength


class CryptoGuardGUI:
    """
    Graphical User Interface for CryptoGuard.
    """
    
    def __init__(self, config: dict = None):
        """
        Initialize the GUI.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.gui_config = self.config.get('gui', {})
        
        # Initialize components with shared key_manager
        self.crypto_engine = CryptoEngine(self.config)
        self.key_manager = KeyManager(self.config)
        self.file_handler = FileHandler(self.config, self.key_manager)
        self.logger = Logger(self.config)
        
        # Setup main window
        self.root = tk.Tk()
        self.setup_window()
        self.create_widgets()
    
    def setup_window(self):
        """Setup the main window."""
        self.root.title(self.gui_config.get('window_title', 'CryptoGuard - Encryption Tool'))
        
        # Window size
        window_size = self.gui_config.get('window_size', '800x600')
        try:
            width, height = map(int, window_size.split('x'))
        except (ValueError, AttributeError):
            width, height = 800, 600
        self.root.geometry(f"{width}x{height}")
        
        # Center window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - width) // 2
        y = (self.root.winfo_screenheight() - height) // 2
        self.root.geometry(f"+{x}+{y}")
        
        # Make window resizable
        self.root.minsize(600, 400)
    
    def create_widgets(self):
        """Create all GUI widgets."""
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_text_tab()
        self.create_file_tab()
        self.create_key_tab()
        self.create_settings_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_text_tab(self):
        """Create the text encryption tab."""
        text_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(text_frame, text="Text Encryption")
        
        # Algorithm selection
        algo_frame = ttk.LabelFrame(text_frame, text="Algorithm", padding=5)
        algo_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.text_algorithm = tk.StringVar(value="aes")
        ttk.Radiobutton(algo_frame, text="AES-256", variable=self.text_algorithm, 
                        value="aes").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(algo_frame, text="Fernet", variable=self.text_algorithm, 
                        value="fernet").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(algo_frame, text="RSA", variable=self.text_algorithm, 
                        value="rsa").pack(side=tk.LEFT, padx=5)
        
        # Password
        password_frame = ttk.Frame(text_frame)
        password_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(password_frame, text="Password:").pack(side=tk.LEFT)
        self.text_password = tk.Entry(password_frame, show="*", width=40)
        self.text_password.pack(side=tk.LEFT, padx=5)
        
        # Show password checkbox
        self.show_password = tk.BooleanVar(value=False)
        ttk.Checkbutton(password_frame, text="Show", variable=self.show_password,
                       command=self.toggle_password_visibility).pack(side=tk.LEFT)
        
        # Input text
        ttk.Label(text_frame, text="Input Text:").pack(anchor=tk.W)
        self.input_text = scrolledtext.ScrolledText(text_frame, height=8, width=70)
        self.input_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Buttons
        button_frame = ttk.Frame(text_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(button_frame, text="Encrypt", command=self.encrypt_text).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Decrypt", command=self.decrypt_text).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_text_fields).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copy", command=self.copy_result).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Paste", command=self.paste_input).pack(side=tk.RIGHT, padx=5)
        
        # Output text
        ttk.Label(text_frame, text="Output:").pack(anchor=tk.W)
        self.output_text = scrolledtext.ScrolledText(text_frame, height=8, width=70)
        self.output_text.pack(fill=tk.BOTH, expand=True)
    
    def create_file_tab(self):
        """Create the file encryption tab."""
        file_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(file_frame, text="File Encryption")
        
        # Algorithm selection
        algo_frame = ttk.LabelFrame(file_frame, text="Algorithm", padding=5)
        algo_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.file_algorithm = tk.StringVar(value="aes")
        ttk.Radiobutton(algo_frame, text="AES-256", variable=self.file_algorithm, 
                        value="aes").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(algo_frame, text="Fernet", variable=self.file_algorithm, 
                        value="fernet").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(algo_frame, text="RSA", variable=self.file_algorithm, 
                        value="rsa").pack(side=tk.LEFT, padx=5)
        
        # Password
        password_frame = ttk.Frame(file_frame)
        password_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(password_frame, text="Password:").pack(side=tk.LEFT)
        self.file_password = tk.Entry(password_frame, show="*", width=40)
        self.file_password.pack(side=tk.LEFT, padx=5)
        
        # File selection
        file_frame_inner = ttk.LabelFrame(file_frame, text="File Operations", padding=10)
        file_frame_inner.pack(fill=tk.X, pady=(0, 10))
        
        # Encrypt file
        ttk.Label(file_frame_inner, text="File to Encrypt:").pack(anchor=tk.W)
        encrypt_file_frame = ttk.Frame(file_frame_inner)
        encrypt_file_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.encrypt_file_path = tk.StringVar()
        ttk.Entry(encrypt_file_frame, textvariable=self.encrypt_file_path, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(encrypt_file_frame, text="Browse", command=self.browse_encrypt_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(encrypt_file_frame, text="Encrypt File", command=self.encrypt_file).pack(side=tk.LEFT, padx=5)
        
        # Decrypt file
        ttk.Label(file_frame_inner, text="File to Decrypt:").pack(anchor=tk.W)
        decrypt_file_frame = ttk.Frame(file_frame_inner)
        decrypt_file_frame.pack(fill=tk.X)
        
        self.decrypt_file_path = tk.StringVar()
        ttk.Entry(decrypt_file_frame, textvariable=self.decrypt_file_path, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(decrypt_file_frame, text="Browse", command=self.browse_decrypt_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(decrypt_file_frame, text="Decrypt File", command=self.decrypt_file).pack(side=tk.LEFT, padx=5)
        
        # Status
        self.file_status = tk.StringVar(value="No file selected")
        ttk.Label(file_frame, textvariable=self.file_status).pack(pady=10)
    
    def create_key_tab(self):
        """Create the key management tab."""
        key_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(key_frame, text="Key Management")
        
        # Generate key
        gen_frame = ttk.LabelFrame(key_frame, text="Generate New Key", padding=10)
        gen_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Key name
        name_frame = ttk.Frame(gen_frame)
        name_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(name_frame, text="Key Name:").pack(side=tk.LEFT)
        self.key_name = tk.StringVar()
        ttk.Entry(name_frame, textvariable=self.key_name, width=30).pack(side=tk.LEFT, padx=5)
        
        # Algorithm
        algo_frame = ttk.Frame(gen_frame)
        algo_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(algo_frame, text="Algorithm:").pack(side=tk.LEFT)
        self.key_algorithm = tk.StringVar(value="aes")
        ttk.Radiobutton(algo_frame, text="AES", variable=self.key_algorithm, value="aes").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(algo_frame, text="Fernet", variable=self.key_algorithm, value="fernet").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(algo_frame, text="RSA", variable=self.key_algorithm, value="rsa").pack(side=tk.LEFT, padx=5)
        
        # Password
        pass_frame = ttk.Frame(gen_frame)
        pass_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(pass_frame, text="Password (optional):").pack(side=tk.LEFT)
        self.key_password = tk.Entry(pass_frame, show="*", width=30)
        self.key_password.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(gen_frame, text="Generate Key", command=self.generate_key).pack(pady=5)
        
        # List keys
        list_frame = ttk.LabelFrame(key_frame, text="Stored Keys", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for keys
        columns = ('name', 'algorithm', 'created', 'encrypted')
        self.key_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        self.key_tree.heading('name', text='Name')
        self.key_tree.heading('algorithm', text='Algorithm')
        self.key_tree.heading('created', text='Created')
        self.key_tree.heading('encrypted', text='Encrypted')
        self.key_tree.pack(fill=tk.BOTH, expand=True)
        
        # Refresh button
        ttk.Button(list_frame, text="Refresh", command=self.refresh_keys).pack(pady=5)
        
        # Load keys
        self.refresh_keys()
    
    def create_settings_tab(self):
        """Create the settings tab."""
        settings_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(settings_frame, text="Settings")
        
        # General settings
        general_frame = ttk.LabelFrame(settings_frame, text="General", padding=10)
        general_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.auto_copy = tk.BooleanVar(value=True)
        ttk.Checkbutton(general_frame, text="Auto-copy results to clipboard", 
                       variable=self.auto_copy).pack(anchor=tk.W)
        
        self.confirm_decrypt = tk.BooleanVar(value=True)
        ttk.Checkbutton(general_frame, text="Confirm before decryption", 
                       variable=self.confirm_decrypt).pack(anchor=tk.W)
        
        # About
        about_frame = ttk.LabelFrame(settings_frame, text="About", padding=10)
        about_frame.pack(fill=tk.X)
        
        ttk.Label(about_frame, text="CryptoGuard - Version 1.0.0").pack(anchor=tk.W)
        ttk.Label(about_frame, text="Encryption / Decryption Tool").pack(anchor=tk.W)
        ttk.Label(about_frame, text="For authorized use only.").pack(anchor=tk.W)
        
        # Warning
        warning_frame = ttk.LabelFrame(settings_frame, text="Warning", padding=10)
        warning_frame.pack(fill=tk.X, pady=(10, 0))
        
        warning_text = tk.Text(warning_frame, height=4, wrap=tk.WORD, bg='lightyellow')
        warning_text.insert(tk.END, "Always keep your encryption keys safe.\n"
                                   "Losing the key means you CANNOT decrypt your data.\n"
                                   "Use encryption ethically and responsibly.")
        warning_text.config(state=tk.DISABLED)
        warning_text.pack(fill=tk.X)
    
    # ==================== Helper Methods ====================
    
    def toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.show_password.get():
            self.text_password.config(show="")
        else:
            self.text_password.config(show="*")
    
    def clear_text_fields(self):
        """Clear input and output text fields."""
        self.input_text.delete(1.0, tk.END)
        self.output_text.delete(1.0, tk.END)
    
    def copy_result(self):
        """Copy output to clipboard."""
        text = self.output_text.get(1.0, tk.END).strip()
        if text:
            if copy_to_clipboard(text):
                self.status_var.set("Copied to clipboard!")
            else:
                self.status_var.set("Failed to copy to clipboard")
    
    def paste_input(self):
        """Paste from clipboard to input."""
        text = paste_from_clipboard()
        if text:
            self.input_text.delete(1.0, tk.END)
            self.input_text.insert(1.0, text)
            self.status_var.set("Pasted from clipboard")
    
    def browse_encrypt_file(self):
        """Browse for file to encrypt."""
        file_path = filedialog.askopenfilename(
            title="Select File to Encrypt",
            filetypes=[("All Files", "*.*")]
        )
        if file_path:
            self.encrypt_file_path.set(file_path)
    
    def browse_decrypt_file(self):
        """Browse for file to decrypt."""
        file_path = filedialog.askopenfilename(
            title="Select File to Decrypt",
            filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
        )
        if file_path:
            self.decrypt_file_path.set(file_path)
    
    def refresh_keys(self):
        """Refresh the key list."""
        # Clear existing items
        for item in self.key_tree.get_children():
            self.key_tree.delete(item)
        
        # Load keys
        keys = self.key_manager.list_keys()
        for key in keys:
            self.key_tree.insert('', tk.END, values=(
                key['name'],
                key['algorithm'].upper(),
                key['created_at'][:10] if key['created_at'] else 'N/A',
                'Yes' if key.get('encrypted') else 'No'
            ))
    
    # ==================== Encryption Operations ====================
    
    def encrypt_text(self):
        """Encrypt text."""
        input_text = self.input_text.get(1.0, tk.END).strip()
        password = self.text_password.get()
        algorithm = self.text_algorithm.get()
        
        if not input_text:
            messagebox.showwarning("Warning", "Please enter text to encrypt.")
            return
        
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return
        
        try:
            encrypted = self.crypto_engine.encrypt_text(input_text, password, algorithm, True)
            
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(1.0, encrypted)
            
            self.status_var.set(f"Text encrypted using {algorithm.upper()}")
            
            # Auto-copy if enabled
            if self.auto_copy.get():
                copy_to_clipboard(encrypted)
                
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")
    
    def decrypt_text(self):
        """Decrypt text."""
        input_text = self.input_text.get(1.0, tk.END).strip()
        password = self.text_password.get()
        algorithm = self.text_algorithm.get()
        
        if not input_text:
            messagebox.showwarning("Warning", "Please enter text to decrypt.")
            return
        
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return
        
        # Confirm if enabled
        if self.confirm_decrypt.get():
            if not messagebox.askyesno("Confirm", "Decrypt this text?"):
                return
        
        try:
            decrypted = self.crypto_engine.decrypt_text(input_text, password, algorithm, True)
            
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(1.0, decrypted)
            
            self.status_var.set(f"Text decrypted using {algorithm.upper()}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")
    
    def encrypt_file(self):
        """Encrypt file."""
        file_path = self.encrypt_file_path.get()
        password = self.file_password.get()
        algorithm = self.file_algorithm.get()
        
        if not file_path:
            messagebox.showwarning("Warning", "Please select a file to encrypt.")
            return
        
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return
        
        try:
            result = self.file_handler.encrypt_file(file_path, password, algorithm)
            
            self.file_status.set(f"Encrypted: {result['output_file']}")
            self.status_var.set("File encrypted successfully!")
            
            messagebox.showinfo("Success", f"File encrypted successfully!\n\nOutput: {result['output_file']}")
            
        except Exception as e:
            messagebox.showerror("Error", f"File encryption failed: {e}")
    
    def decrypt_file(self):
        """Decrypt file."""
        file_path = self.decrypt_file_path.get()
        password = self.file_password.get()
        
        if not file_path:
            messagebox.showwarning("Warning", "Please select a file to decrypt.")
            return
        
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return
        
        # Confirm if enabled
        if self.confirm_decrypt.get():
            if not messagebox.askyesno("Confirm", "Decrypt this file?"):
                return
        
        try:
            result = self.file_handler.decrypt_file(file_path, password)
            
            self.file_status.set(f"Decrypted: {result['output_file']}")
            self.status_var.set("File decrypted successfully!")
            
            messagebox.showinfo("Success", f"File decrypted successfully!\n\nOutput: {result['output_file']}")
            
        except Exception as e:
            messagebox.showerror("Error", f"File decryption failed: {e}")
    
    def generate_key(self):
        """Generate a new encryption key."""
        name = self.key_name.get()
        algorithm = self.key_algorithm.get()
        password = self.key_password.get() or None
        
        if not name:
            messagebox.showwarning("Warning", "Please enter a key name.")
            return
        
        try:
            if algorithm == 'aes':
                result = self.key_manager.generate_aes_key(name, password)
            elif algorithm == 'fernet':
                result = self.key_manager.generate_fernet_key(name, password)
            elif algorithm == 'rsa':
                result = self.key_manager.generate_rsa_keypair(name, password)
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            messagebox.showinfo("Success", f"Key '{name}' generated successfully!")
            self.refresh_keys()
            
            # Clear fields
            self.key_name.set("")
            self.key_password.delete(0, tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {e}")
    
    def run(self):
        """Run the GUI application."""
        self.root.mainloop()


def load_config(config_path: str = None) -> dict:
    """Load configuration from file."""
    if not YAML_AVAILABLE:
        return {}
    
    if config_path is None:
        # Try default locations relative to project root
        project_root = Path(__file__).parent
        config_path = str(project_root / 'config.yaml')
    
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"Error loading config: {e}")
        return {}


def main():
    """Main entry point for GUI."""
    config = load_config()
    app = CryptoGuardGUI(config)
    app.run()


if __name__ == '__main__':
    main()
