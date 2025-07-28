# Password Manager

This is a small personal project implementing a basic password manager in Python.

## Overview

- Encryption key is derived from the user's master password using **PBKDF2** with a **static** salt.
- Passwords are encrypted and decrypted using **symmetric encryption (Fernet)** from the `cryptography` library.
- The encrypted json is saved in a local file (`vault.dat`).
- The user interacts through a simple command line interface to add and retrieve passwords.

## Usage

```bash
python pw_manager.py
