# Secure Vault - Password Manager

Secure Vault is a lightweight, cross-platform password manager built in Python. It allows users to create encrypted vaults to store login credentials securely. The app includes a graphical interface for ease of use and several security-focused features.

---

## Features

* Vaults: Multiple independent vaults, each stored in its own folder.
* Entries: Save and retrieve credentials for websites or apps.
* Password Generator: Create strong, random passwords.
* Clipboard Management: Copy passwords safely with auto-clear.
* GUI Interface: Easy-to-use interface using Tkinter.
* Secure Storage: AES-GCM encryption with PBKDF2 key derivation.
* Plaintext Password Display: Optionally view passwords when loading saved entries.
* Vault Lock: Clears all sensitive data from memory.

---

## Installation

1. Clone the repository

```
git clone https://github.com/ae3erdion/Secure-Vault.git
cd Secure-Vault
```

2. Create a Python virtual environment (recommended)

```
python3 -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate         # Windows
```

3. Install dependencies

```
pip install -r requirements.txt
```

Dependencies include:

* cryptography>=36.0.0
* tkinter (included with most Python installations)

> Linux note: If you get a Tkinter error, install it separately:
>
> * Ubuntu/Debian: `sudo apt install python3-tk`
> * Fedora: `sudo dnf install python3-tkinter`

4. Run the application

```
python3 main.py
```

---

## Usage

### First-Time Setup

1. Enter a vault name and a master password.
2. If the vault does not exist, it will be created.

### Unlock Existing Vault

1. Enter the vault name and master password to unlock it.

### Main Window

* Generate Password: Creates a secure random password (masked) and copies it to clipboard.
* Save Entry: Save site, username, and password to the vault.
* Load Saved Passwords: Opens a dropdown of saved sites, displays the password in plaintext, and copies it to clipboard.
* Copy Password: Copy the current password in the entry field.
* Lock Vault: Clears sensitive data from memory and returns to login screen.

---

## Project Structure

```
secure-vault/
│
├─ main.py                  # GUI application
├─ secure_vault.py          # Vault management and encryption
├─ secure_clipboard.py      # Clipboard auto-clear functionality
├─ password_generator.py    # Random password generator
├─ vaults/                  # Folder where vaults are stored
├─ README.md                # Project description and instructions
├─ requirements.txt         # Python dependencies
└─ .gitignore               # Files/folders to ignore in Git
```

---

## Security Notes

* Each vault is isolated, stored in its own folder with encrypted entries.
* Master password is never stored in plaintext.
* Clipboard auto-clears after 15 seconds to reduce exposure.
* Locking the vault clears all sensitive data from memory.
* Vaults are encrypted using AES-GCM with keys derived via PBKDF2HMAC.
* Auto-lock triggers after a period of inactivity (default 5 minutes), ensuring the vault is never left open unattended.

---

## Contributing

Contributions, bug reports, and feature requests are welcome! Please open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License.
