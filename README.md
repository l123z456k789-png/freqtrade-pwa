# Private encrypted ledger

A static, installable lock screen. The application bundle and the latest
holdings snapshot are AES-256-GCM ciphertext derived from a passphrase with
PBKDF2-HMAC-SHA256. This repository contains no plaintext holdings, API keys,
passphrases, or strategy details.

Open the deployed page and enter the private passphrase to decrypt the app
locally in the browser. No GitHub token is required.
