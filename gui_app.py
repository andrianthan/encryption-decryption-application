#!/usr/bin/env python3
"""
Encryption/Decryption Application - GUI
A user-friendly graphical interface for file encryption and decryption.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import json
from datetime import datetime
from typing import Optional, List, Dict
import threading

from src.crypto import ALGORITHMS
from src.utils.input_validator import validate_algorithm, validate_file_exists
from main import _load_or_generate_key, _get_default_key_path, _detect_algorithm_from_filename
from main import DATA_DIR, KEYS_DIR, ENCRYPTED_DIR, DECRYPTED_DIR, DEFAULT_ALGORITHM


class ActivityLogger:
    """Manages activity log for the application."""

    def __init__(self, log_file: Path = DATA_DIR / "activity_log.json"):
        self.log_file = log_file
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.activities = self._load_log()

    def _load_log(self) -> List[Dict]:
        """Load activity log from file."""
        if self.log_file.exists():
            try:
                with open(self.log_file, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []

    def _save_log(self):
        """Save activity log to file."""
        with open(self.log_file, 'w') as f:
            json.dump(self.activities, f, indent=2)

    def log_activity(self, action: str, subject: str, result: str, details: str = ""):
        """Add an activity to the log."""
        activity = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "subject": subject,
            "result": result,
            "details": details
        }
        self.activities.insert(0, activity)  # Most recent first
        self._save_log()

    def get_recent(self, limit: int = 10) -> List[Dict]:
        """Get recent activities."""
        return self.activities[:limit]


class EncryptionApp:
    """Main GUI application for encryption/decryption."""

    def __init__(self, root):
        self.root = root
        self.root.title("Encryption & Decryption Tool")
        self.root.geometry("900x700")

        # Initialize activity logger
        self.activity_logger = ActivityLogger()

        # Configure style
        self.setup_style()

        # Create main container
        self.main_container = ttk.Frame(root, padding="10")
        self.main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        self.main_container.columnconfigure(0, weight=1)
        self.main_container.rowconfigure(1, weight=1)

        # Create header
        self.create_header()

        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))

        # Create tabs
        self.create_home_tab()
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_keys_tab()
        self.create_activity_tab()
        self.create_settings_tab()

    def setup_style(self):
        """Configure application styling."""
        style = ttk.Style()
        style.theme_use('clam')

        # Define colors
        bg_color = "#f5f5f5"
        accent_color = "#2196F3"
        success_color = "#4CAF50"
        danger_color = "#f44336"

        # Configure styles
        style.configure("Header.TLabel", font=("Helvetica", 16, "bold"))
        style.configure("SubHeader.TLabel", font=("Helvetica", 12, "bold"))
        style.configure("Status.TLabel", foreground=success_color, font=("Helvetica", 10))
        style.configure("Primary.TButton", font=("Helvetica", 11))
        style.configure("Accent.TButton", background=accent_color, font=("Helvetica", 11, "bold"))

    def create_header(self):
        """Create application header."""
        header = ttk.Frame(self.main_container)
        header.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # App title
        title = ttk.Label(header, text="🔒 Encryption & Decryption Tool", style="Header.TLabel")
        title.grid(row=0, column=0, sticky=tk.W)

        # Status
        status = ttk.Label(header, text="All secure ✓", style="Status.TLabel")
        status.grid(row=0, column=1, sticky=tk.E, padx=(10, 0))

        header.columnconfigure(1, weight=1)

    def create_home_tab(self):
        """Create the Home tab."""
        home_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(home_frame, text="Home")

        # Quick actions section
        actions_label = ttk.Label(home_frame, text="Quick Actions", style="SubHeader.TLabel")
        actions_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 15))

        # Drag and drop area (simulated)
        drop_frame = ttk.LabelFrame(home_frame, text="Drag & Drop Files Here", padding="40")
        drop_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 20))

        drop_label = ttk.Label(drop_frame, text="Drop files to encrypt or decrypt\n(or use the buttons below)")
        drop_label.grid(row=0, column=0)

        # Action buttons
        button_frame = ttk.Frame(home_frame)
        button_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 20))

        encrypt_btn = ttk.Button(button_frame, text="🔒 Encrypt Files",
                                command=lambda: self.notebook.select(1), style="Primary.TButton")
        encrypt_btn.grid(row=0, column=0, padx=(0, 10))

        decrypt_btn = ttk.Button(button_frame, text="🔓 Decrypt Files",
                                command=lambda: self.notebook.select(2), style="Primary.TButton")
        decrypt_btn.grid(row=0, column=1, padx=(0, 10))

        keys_btn = ttk.Button(button_frame, text="🔑 Manage Keys",
                             command=lambda: self.notebook.select(3), style="Primary.TButton")
        keys_btn.grid(row=0, column=2)

        # Recent activity section
        recent_label = ttk.Label(home_frame, text="Recent Activity", style="SubHeader.TLabel")
        recent_label.grid(row=3, column=0, sticky=tk.W, pady=(10, 10))

        # Activity list
        self.activity_text = tk.Text(home_frame, height=10, width=70, state=tk.DISABLED)
        self.activity_text.grid(row=4, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Scrollbar for activity
        scrollbar = ttk.Scrollbar(home_frame, orient=tk.VERTICAL, command=self.activity_text.yview)
        scrollbar.grid(row=4, column=1, sticky=(tk.N, tk.S))
        self.activity_text.config(yscrollcommand=scrollbar.set)

        # Load recent activity
        self.update_recent_activity()

        home_frame.columnconfigure(0, weight=1)
        home_frame.rowconfigure(4, weight=1)

    def update_recent_activity(self):
        """Update the recent activity display."""
        self.activity_text.config(state=tk.NORMAL)
        self.activity_text.delete(1.0, tk.END)

        recent = self.activity_logger.get_recent(10)
        if not recent:
            self.activity_text.insert(tk.END, "No recent activity")
        else:
            for activity in recent:
                timestamp = datetime.fromisoformat(activity["timestamp"]).strftime("%Y-%m-%d %H:%M")
                line = f"• {timestamp} - {activity['action']}: {activity['subject']} - {activity['result']}\n"
                self.activity_text.insert(tk.END, line)

        self.activity_text.config(state=tk.DISABLED)

    def create_encrypt_tab(self):
        """Create the Encrypt tab."""
        encrypt_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(encrypt_frame, text="Encrypt")

        # Title
        title = ttk.Label(encrypt_frame, text="Encrypt Files", style="SubHeader.TLabel")
        title.grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 20))

        # Source selection
        ttk.Label(encrypt_frame, text="Source File:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.encrypt_source_var = tk.StringVar()
        source_entry = ttk.Entry(encrypt_frame, textvariable=self.encrypt_source_var, width=50)
        source_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 5))

        browse_btn = ttk.Button(encrypt_frame, text="Browse...", command=self.browse_encrypt_source)
        browse_btn.grid(row=1, column=2, pady=5)

        # Output destination
        ttk.Label(encrypt_frame, text="Output:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.encrypt_output_var = tk.StringVar(value="Auto (encrypted folder)")
        output_entry = ttk.Entry(encrypt_frame, textvariable=self.encrypt_output_var, width=50)
        output_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 5))

        output_btn = ttk.Button(encrypt_frame, text="Change...", command=self.browse_encrypt_output)
        output_btn.grid(row=2, column=2, pady=5)

        # Algorithm selection
        ttk.Label(encrypt_frame, text="Algorithm:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.encrypt_algorithm_var = tk.StringVar(value=DEFAULT_ALGORITHM)
        algorithm_combo = ttk.Combobox(encrypt_frame, textvariable=self.encrypt_algorithm_var,
                                      values=list(ALGORITHMS.keys()), state="readonly", width=20)
        algorithm_combo.grid(row=3, column=1, sticky=tk.W, pady=5, padx=(10, 5))

        # Key file
        ttk.Label(encrypt_frame, text="Key File:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.encrypt_key_var = tk.StringVar(value="Auto (will be generated)")
        key_entry = ttk.Entry(encrypt_frame, textvariable=self.encrypt_key_var, width=50)
        key_entry.grid(row=4, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 5))

        key_btn = ttk.Button(encrypt_frame, text="Select...", command=self.browse_encrypt_key)
        key_btn.grid(row=4, column=2, pady=5)

        # Options
        options_frame = ttk.LabelFrame(encrypt_frame, text="Options", padding="10")
        options_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=15)

        self.encrypt_gen_key_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Auto-generate key if not found",
                       variable=self.encrypt_gen_key_var).grid(row=0, column=0, sticky=tk.W)

        # Action buttons
        button_frame = ttk.Frame(encrypt_frame)
        button_frame.grid(row=6, column=0, columnspan=3, pady=20)

        encrypt_btn = ttk.Button(button_frame, text="🔒 Encrypt",
                                command=self.perform_encryption, style="Accent.TButton")
        encrypt_btn.grid(row=0, column=0, padx=5)

        cancel_btn = ttk.Button(button_frame, text="Cancel", command=self.clear_encrypt_form)
        cancel_btn.grid(row=0, column=1, padx=5)

        # Status/Progress
        self.encrypt_status_var = tk.StringVar(value="")
        status_label = ttk.Label(encrypt_frame, textvariable=self.encrypt_status_var)
        status_label.grid(row=7, column=0, columnspan=3, pady=10)

        encrypt_frame.columnconfigure(1, weight=1)

    def create_decrypt_tab(self):
        """Create the Decrypt tab."""
        decrypt_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(decrypt_frame, text="Decrypt")

        # Title
        title = ttk.Label(decrypt_frame, text="Decrypt Files", style="SubHeader.TLabel")
        title.grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 20))

        # Encrypted file selection
        ttk.Label(decrypt_frame, text="Encrypted File:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.decrypt_source_var = tk.StringVar()
        source_entry = ttk.Entry(decrypt_frame, textvariable=self.decrypt_source_var, width=50)
        source_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 5))

        browse_btn = ttk.Button(decrypt_frame, text="Browse...", command=self.browse_decrypt_source)
        browse_btn.grid(row=1, column=2, pady=5)

        # Output destination
        ttk.Label(decrypt_frame, text="Output:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.decrypt_output_var = tk.StringVar(value="Auto (decrypted folder)")
        output_entry = ttk.Entry(decrypt_frame, textvariable=self.decrypt_output_var, width=50)
        output_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 5))

        output_btn = ttk.Button(decrypt_frame, text="Change...", command=self.browse_decrypt_output)
        output_btn.grid(row=2, column=2, pady=5)

        # Algorithm (auto-detected)
        ttk.Label(decrypt_frame, text="Algorithm:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.decrypt_algorithm_var = tk.StringVar(value="Auto-detect from filename")
        algorithm_combo = ttk.Combobox(decrypt_frame, textvariable=self.decrypt_algorithm_var,
                                      values=["Auto-detect from filename"] + list(ALGORITHMS.keys()),
                                      state="readonly", width=20)
        algorithm_combo.grid(row=3, column=1, sticky=tk.W, pady=5, padx=(10, 5))

        # Key file
        ttk.Label(decrypt_frame, text="Key File:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.decrypt_key_var = tk.StringVar(value="Auto (based on algorithm)")
        key_entry = ttk.Entry(decrypt_frame, textvariable=self.decrypt_key_var, width=50)
        key_entry.grid(row=4, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 5))

        key_btn = ttk.Button(decrypt_frame, text="Select...", command=self.browse_decrypt_key)
        key_btn.grid(row=4, column=2, pady=5)

        # Info box
        info_frame = ttk.Frame(decrypt_frame)
        info_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=15)

        info_text = "ℹ️ Your key never leaves this device. All decryption happens locally."
        ttk.Label(info_frame, text=info_text, foreground="blue").grid(row=0, column=0)

        # Action buttons
        button_frame = ttk.Frame(decrypt_frame)
        button_frame.grid(row=6, column=0, columnspan=3, pady=20)

        decrypt_btn = ttk.Button(button_frame, text="🔓 Decrypt",
                                command=self.perform_decryption, style="Accent.TButton")
        decrypt_btn.grid(row=0, column=0, padx=5)

        cancel_btn = ttk.Button(button_frame, text="Cancel", command=self.clear_decrypt_form)
        cancel_btn.grid(row=0, column=1, padx=5)

        # Status/Progress
        self.decrypt_status_var = tk.StringVar(value="")
        status_label = ttk.Label(decrypt_frame, textvariable=self.decrypt_status_var)
        status_label.grid(row=7, column=0, columnspan=3, pady=10)

        decrypt_frame.columnconfigure(1, weight=1)

    def create_keys_tab(self):
        """Create the Key Management tab."""
        keys_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(keys_frame, text="Keys")

        # Title
        title = ttk.Label(keys_frame, text="Key Management", style="SubHeader.TLabel")
        title.grid(row=0, column=0, sticky=tk.W, pady=(0, 20))

        # Action buttons
        button_frame = ttk.Frame(keys_frame)
        button_frame.grid(row=1, column=0, sticky=tk.W, pady=(0, 10))

        ttk.Button(button_frame, text="Generate New Key",
                  command=self.generate_new_key).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(button_frame, text="Import Key",
                  command=self.import_key).grid(row=0, column=1, padx=(0, 5))
        ttk.Button(button_frame, text="Refresh List",
                  command=self.refresh_key_list).grid(row=0, column=2)

        # Keys list
        list_frame = ttk.LabelFrame(keys_frame, text="Available Keys", padding="10")
        list_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)

        # Create treeview for keys
        columns = ("filename", "algorithm", "size", "modified")
        self.keys_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)

        self.keys_tree.heading("filename", text="Key File")
        self.keys_tree.heading("algorithm", text="Algorithm")
        self.keys_tree.heading("size", text="Size")
        self.keys_tree.heading("modified", text="Modified")

        self.keys_tree.column("filename", width=250)
        self.keys_tree.column("algorithm", width=150)
        self.keys_tree.column("size", width=100)
        self.keys_tree.column("modified", width=150)

        self.keys_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.keys_tree.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.keys_tree.config(yscrollcommand=scrollbar.set)

        # Key actions
        key_actions = ttk.Frame(keys_frame)
        key_actions.grid(row=3, column=0, sticky=tk.W, pady=10)

        ttk.Button(key_actions, text="Open Key Folder",
                  command=self.open_keys_folder).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(key_actions, text="Export Selected",
                  command=self.export_selected_key).grid(row=0, column=1, padx=(0, 5))
        ttk.Button(key_actions, text="Delete Selected",
                  command=self.delete_selected_key).grid(row=0, column=2)

        # Load keys
        self.refresh_key_list()

        keys_frame.columnconfigure(0, weight=1)
        keys_frame.rowconfigure(2, weight=1)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

    def create_activity_tab(self):
        """Create the Activity Log tab."""
        activity_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(activity_frame, text="Activity Log")

        # Title
        title = ttk.Label(activity_frame, text="Activity Log", style="SubHeader.TLabel")
        title.grid(row=0, column=0, sticky=tk.W, pady=(0, 20))

        # Action buttons
        button_frame = ttk.Frame(activity_frame)
        button_frame.grid(row=1, column=0, sticky=tk.W, pady=(0, 10))

        ttk.Button(button_frame, text="Refresh",
                  command=self.refresh_activity_log).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(button_frame, text="Export Log",
                  command=self.export_activity_log).grid(row=0, column=1, padx=(0, 5))
        ttk.Button(button_frame, text="Clear Log",
                  command=self.clear_activity_log).grid(row=0, column=2)

        # Activity log display
        log_frame = ttk.Frame(activity_frame)
        log_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Create treeview for activity log
        columns = ("timestamp", "action", "subject", "result")
        self.activity_tree = ttk.Treeview(log_frame, columns=columns, show="headings", height=20)

        self.activity_tree.heading("timestamp", text="Timestamp")
        self.activity_tree.heading("action", text="Action")
        self.activity_tree.heading("subject", text="Subject")
        self.activity_tree.heading("result", text="Result")

        self.activity_tree.column("timestamp", width=180)
        self.activity_tree.column("action", width=120)
        self.activity_tree.column("subject", width=300)
        self.activity_tree.column("result", width=150)

        self.activity_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Scrollbar
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.activity_tree.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.activity_tree.config(yscrollcommand=scrollbar.set)

        # Load activity log
        self.refresh_activity_log()

        activity_frame.columnconfigure(0, weight=1)
        activity_frame.rowconfigure(2, weight=1)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

    def create_settings_tab(self):
        """Create the Settings tab."""
        settings_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(settings_frame, text="Settings")

        # Title
        title = ttk.Label(settings_frame, text="Settings", style="SubHeader.TLabel")
        title.grid(row=0, column=0, sticky=tk.W, pady=(0, 20))

        # Security settings
        security_frame = ttk.LabelFrame(settings_frame, text="Security", padding="10")
        security_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(security_frame, text="Default Algorithm:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.settings_algorithm_var = tk.StringVar(value=DEFAULT_ALGORITHM)
        ttk.Combobox(security_frame, textvariable=self.settings_algorithm_var,
                    values=list(ALGORITHMS.keys()), state="readonly", width=20).grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)

        # Directory settings
        dir_frame = ttk.LabelFrame(settings_frame, text="Directories", padding="10")
        dir_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(dir_frame, text=f"Data Directory: {DATA_DIR}").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Label(dir_frame, text=f"Keys Directory: {KEYS_DIR}").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Label(dir_frame, text=f"Encrypted Files: {ENCRYPTED_DIR}").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Label(dir_frame, text=f"Decrypted Files: {DECRYPTED_DIR}").grid(row=3, column=0, sticky=tk.W, pady=5)

        # About section
        about_frame = ttk.LabelFrame(settings_frame, text="About", padding="10")
        about_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        about_text = """Encryption & Decryption Tool v1.0

A secure, local-first file encryption application.
All encryption happens on your device - keys never leave your computer.

Supported Algorithms:
• AES-GCM (recommended)
• AES-CCM
• AES-SIV
• AES-GCM-SIV
• ChaCha20-Poly1305
• AES-CBC + HMAC"""

        ttk.Label(about_frame, text=about_text, justify=tk.LEFT).grid(row=0, column=0, sticky=tk.W)

        settings_frame.columnconfigure(0, weight=1)

    # File browser methods
    def browse_encrypt_source(self):
        """Browse for file to encrypt."""
        filename = filedialog.askopenfilename(title="Select file to encrypt")
        if filename:
            self.encrypt_source_var.set(filename)

    def browse_encrypt_output(self):
        """Browse for encryption output location."""
        filename = filedialog.asksaveasfilename(
            title="Save encrypted file as",
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        if filename:
            self.encrypt_output_var.set(filename)

    def browse_encrypt_key(self):
        """Browse for encryption key file."""
        filename = filedialog.askopenfilename(
            title="Select key file",
            initialdir=KEYS_DIR,
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )
        if filename:
            self.encrypt_key_var.set(filename)

    def browse_decrypt_source(self):
        """Browse for file to decrypt."""
        filename = filedialog.askopenfilename(
            title="Select encrypted file",
            initialdir=ENCRYPTED_DIR,
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        if filename:
            self.decrypt_source_var.set(filename)
            # Try to auto-detect algorithm
            algo = _detect_algorithm_from_filename(Path(filename).name)
            if algo:
                self.decrypt_algorithm_var.set(algo)

    def browse_decrypt_output(self):
        """Browse for decryption output location."""
        filename = filedialog.asksaveasfilename(
            title="Save decrypted file as",
            initialdir=DECRYPTED_DIR
        )
        if filename:
            self.decrypt_output_var.set(filename)

    def browse_decrypt_key(self):
        """Browse for decryption key file."""
        filename = filedialog.askopenfilename(
            title="Select key file",
            initialdir=KEYS_DIR,
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )
        if filename:
            self.decrypt_key_var.set(filename)

    # Encryption/Decryption operations
    def perform_encryption(self):
        """Perform file encryption."""
        # Validate inputs
        source = self.encrypt_source_var.get()
        if not source:
            messagebox.showerror("Error", "Please select a file to encrypt")
            return

        if not Path(source).exists():
            messagebox.showerror("Error", f"Source file not found: {source}")
            return

        # Get parameters
        algo = self.encrypt_algorithm_var.get()
        output = self.encrypt_output_var.get()
        key_file = self.encrypt_key_var.get()
        gen_key = self.encrypt_gen_key_var.get()

        # Determine output path
        if output == "Auto (encrypted folder)" or not output:
            input_path = Path(source)
            output = str(ENCRYPTED_DIR / f"{input_path.name}.{algo}.enc")

        # Determine key path
        if key_file == "Auto (will be generated)" or not key_file:
            key_path = _get_default_key_path(algo)
        else:
            key_path = Path(key_file)

        # Perform encryption in thread
        def encrypt_thread():
            try:
                self.encrypt_status_var.set("Encrypting...")

                # Ensure output directory exists
                Path(output).parent.mkdir(parents=True, exist_ok=True)

                # Load or generate key
                key = _load_or_generate_key(algo, key_path, gen_key)

                # Get algorithm module
                module = ALGORITHMS[algo]

                # Encrypt
                if algo == "aes_0cb3":
                    aes_key, hmac_key = key
                    module.encrypt_file(str(source), str(output), aes_key, hmac_key)
                else:
                    module.encrypt_file(str(source), str(output), key)

                # Log activity
                self.activity_logger.log_activity(
                    "Encrypt",
                    Path(source).name,
                    "Success",
                    f"Algorithm: {algo}, Output: {output}"
                )

                self.encrypt_status_var.set(f"✓ Success! Encrypted to: {output}")
                self.update_recent_activity()
                messagebox.showinfo("Success", f"File encrypted successfully!\n\nOutput: {output}")

            except Exception as e:
                self.encrypt_status_var.set(f"✗ Error: {str(e)}")
                self.activity_logger.log_activity(
                    "Encrypt",
                    Path(source).name,
                    "Failed",
                    str(e)
                )
                messagebox.showerror("Encryption Failed", str(e))

        threading.Thread(target=encrypt_thread, daemon=True).start()

    def perform_decryption(self):
        """Perform file decryption."""
        # Validate inputs
        source = self.decrypt_source_var.get()
        if not source:
            messagebox.showerror("Error", "Please select a file to decrypt")
            return

        if not Path(source).exists():
            messagebox.showerror("Error", f"Encrypted file not found: {source}")
            return

        # Get parameters
        algo = self.decrypt_algorithm_var.get()
        output = self.decrypt_output_var.get()
        key_file = self.decrypt_key_var.get()

        # Auto-detect algorithm if needed
        if algo == "Auto-detect from filename":
            algo = _detect_algorithm_from_filename(Path(source).name)
            if not algo:
                messagebox.showerror("Error", "Could not auto-detect algorithm. Please select manually.")
                return

        # Determine output path
        if output == "Auto (decrypted folder)" or not output:
            input_path = Path(source)
            output_name = input_path.stem if input_path.suffix == ".enc" else input_path.name
            if "." in output_name and output_name.split(".")[-1] in ALGORITHMS:
                output_name = ".".join(output_name.split(".")[:-1])
            output = str(DECRYPTED_DIR / output_name)

        # Determine key path
        if key_file == "Auto (based on algorithm)" or not key_file:
            key_path = _get_default_key_path(algo)
        else:
            key_path = Path(key_file)

        if not key_path.exists():
            messagebox.showerror("Error", f"Key file not found: {key_path}")
            return

        # Perform decryption in thread
        def decrypt_thread():
            try:
                self.decrypt_status_var.set("Decrypting...")

                # Ensure output directory exists
                Path(output).parent.mkdir(parents=True, exist_ok=True)

                # Load key
                key = _load_or_generate_key(algo, key_path, generate_if_missing=False)

                # Get algorithm module
                module = ALGORITHMS[algo]

                # Decrypt
                if algo == "aes_0cb3":
                    aes_key, hmac_key = key
                    module.decrypt_file(str(source), str(output), aes_key, hmac_key)
                else:
                    module.decrypt_file(str(source), str(output), key)

                # Log activity
                self.activity_logger.log_activity(
                    "Decrypt",
                    Path(source).name,
                    "Success",
                    f"Algorithm: {algo}, Output: {output}"
                )

                self.decrypt_status_var.set(f"✓ Success! Decrypted to: {output}")
                self.update_recent_activity()
                messagebox.showinfo("Success", f"File decrypted successfully!\n\nOutput: {output}")

            except Exception as e:
                self.decrypt_status_var.set(f"✗ Error: {str(e)}")
                self.activity_logger.log_activity(
                    "Decrypt",
                    Path(source).name,
                    "Failed",
                    str(e)
                )
                messagebox.showerror("Decryption Failed", str(e))

        threading.Thread(target=decrypt_thread, daemon=True).start()

    def clear_encrypt_form(self):
        """Clear encryption form."""
        self.encrypt_source_var.set("")
        self.encrypt_output_var.set("Auto (encrypted folder)")
        self.encrypt_algorithm_var.set(DEFAULT_ALGORITHM)
        self.encrypt_key_var.set("Auto (will be generated)")
        self.encrypt_status_var.set("")

    def clear_decrypt_form(self):
        """Clear decryption form."""
        self.decrypt_source_var.set("")
        self.decrypt_output_var.set("Auto (decrypted folder)")
        self.decrypt_algorithm_var.set("Auto-detect from filename")
        self.decrypt_key_var.set("Auto (based on algorithm)")
        self.decrypt_status_var.set("")

    # Key management methods
    def refresh_key_list(self):
        """Refresh the keys list."""
        # Clear existing items
        for item in self.keys_tree.get_children():
            self.keys_tree.delete(item)

        # Ensure keys directory exists
        KEYS_DIR.mkdir(parents=True, exist_ok=True)

        # List key files
        for key_file in sorted(KEYS_DIR.glob("*.key")):
            stat = key_file.stat()
            size = f"{stat.st_size} bytes"
            modified = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")

            # Try to determine algorithm from filename
            algo = "Unknown"
            for alg_name in ALGORITHMS.keys():
                if alg_name in key_file.stem:
                    algo = alg_name
                    break

            self.keys_tree.insert("", tk.END, values=(
                key_file.name,
                algo,
                size,
                modified
            ))

    def generate_new_key(self):
        """Generate a new encryption key."""
        # Ask for algorithm
        algo = tk.simpledialog.askstring(
            "Generate Key",
            f"Enter algorithm name:\n{', '.join(ALGORITHMS.keys())}",
            initialvalue=DEFAULT_ALGORITHM
        )

        if not algo or algo not in ALGORITHMS:
            return

        # Generate key file name
        key_name = tk.simpledialog.askstring(
            "Key Name",
            "Enter a name for the key file:",
            initialvalue=f"{algo}_{datetime.now().strftime('%Y%m%d')}.key"
        )

        if not key_name:
            return

        if not key_name.endswith(".key"):
            key_name += ".key"

        key_path = KEYS_DIR / key_name

        if key_path.exists():
            if not messagebox.askyesno("Confirm", f"Key file {key_name} already exists. Overwrite?"):
                return

        try:
            # Generate key
            key = _load_or_generate_key(algo, key_path, generate_if_missing=True)

            self.activity_logger.log_activity(
                "Generate Key",
                key_name,
                "Success",
                f"Algorithm: {algo}"
            )

            self.refresh_key_list()
            self.update_recent_activity()
            messagebox.showinfo("Success", f"Key generated successfully!\n\nLocation: {key_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate key: {str(e)}")

    def import_key(self):
        """Import an existing key file."""
        filename = filedialog.askopenfilename(
            title="Select key file to import",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )

        if not filename:
            return

        import shutil
        try:
            dest = KEYS_DIR / Path(filename).name
            shutil.copy2(filename, dest)

            self.activity_logger.log_activity(
                "Import Key",
                Path(filename).name,
                "Success",
                f"Imported to: {dest}"
            )

            self.refresh_key_list()
            self.update_recent_activity()
            messagebox.showinfo("Success", "Key imported successfully!")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to import key: {str(e)}")

    def open_keys_folder(self):
        """Open the keys folder in file manager."""
        import subprocess
        import platform

        KEYS_DIR.mkdir(parents=True, exist_ok=True)

        if platform.system() == "Darwin":  # macOS
            subprocess.run(["open", str(KEYS_DIR)])
        elif platform.system() == "Windows":
            subprocess.run(["explorer", str(KEYS_DIR)])
        else:  # Linux
            subprocess.run(["xdg-open", str(KEYS_DIR)])

    def export_selected_key(self):
        """Export selected key to a location."""
        selection = self.keys_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a key to export")
            return

        key_name = self.keys_tree.item(selection[0])["values"][0]
        key_path = KEYS_DIR / key_name

        dest = filedialog.asksaveasfilename(
            title="Export key as",
            initialfile=key_name,
            defaultextension=".key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )

        if not dest:
            return

        import shutil
        try:
            shutil.copy2(key_path, dest)
            messagebox.showinfo("Success", f"Key exported to: {dest}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export key: {str(e)}")

    def delete_selected_key(self):
        """Delete selected key."""
        selection = self.keys_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a key to delete")
            return

        key_name = self.keys_tree.item(selection[0])["values"][0]

        if not messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete the key '{key_name}'?\n\n"
            "This action cannot be undone. Files encrypted with this key "
            "will become permanently inaccessible!"
        ):
            return

        key_path = KEYS_DIR / key_name

        try:
            key_path.unlink()

            self.activity_logger.log_activity(
                "Delete Key",
                key_name,
                "Success",
                "Key permanently deleted"
            )

            self.refresh_key_list()
            self.update_recent_activity()
            messagebox.showinfo("Success", "Key deleted successfully")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete key: {str(e)}")

    # Activity log methods
    def refresh_activity_log(self):
        """Refresh the activity log display."""
        # Clear existing items
        for item in self.activity_tree.get_children():
            self.activity_tree.delete(item)

        # Load activities
        activities = self.activity_logger.activities

        for activity in activities:
            timestamp = datetime.fromisoformat(activity["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            self.activity_tree.insert("", tk.END, values=(
                timestamp,
                activity["action"],
                activity["subject"],
                activity["result"]
            ))

    def export_activity_log(self):
        """Export activity log to file."""
        filename = filedialog.asksaveasfilename(
            title="Export activity log",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )

        if not filename:
            return

        try:
            if filename.endswith(".csv"):
                import csv
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=["timestamp", "action", "subject", "result", "details"])
                    writer.writeheader()
                    writer.writerows(self.activity_logger.activities)
            else:
                with open(filename, 'w') as f:
                    json.dump(self.activity_logger.activities, f, indent=2)

            messagebox.showinfo("Success", f"Activity log exported to: {filename}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to export log: {str(e)}")

    def clear_activity_log(self):
        """Clear the activity log."""
        if not messagebox.askyesno(
            "Confirm Clear",
            "Are you sure you want to clear the activity log?\n\n"
            "This action cannot be undone."
        ):
            return

        self.activity_logger.activities = []
        self.activity_logger._save_log()
        self.refresh_activity_log()
        self.update_recent_activity()
        messagebox.showinfo("Success", "Activity log cleared")


def main():
    """Main entry point for the GUI application."""
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
