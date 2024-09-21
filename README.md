# Password-Safe
This application is a graphical password manager built using Python and Tkinter. It allows users to:

Generate secure random passwords
Store website credentials (site, username, password) securely
Retrieve stored credentials for specific websites
Encrypt all sensitive data before saving to a JSON file
Decrypt data when retrieving credentials

Key features include:

A user-friendly GUI for easy interaction
Automatic password generation
Secure storage using encryption (AES via the Fernet recipe)
Search functionality to quickly find stored credentials
Clipboard integration for easy password copying

The app uses a master password for encryption/decryption, ensuring that even if the JSON file is compromised, the stored credentials remain secure. This makes it a practical tool for managing multiple accounts while maintaining good security practices.
