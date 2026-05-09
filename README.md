# CipherVault — Web-Based Text Encryption Tool
**Information Security Assignment A2**

---

## Setup & Run

### 1. Install Dependencies
```bash
pip install flask flask-cors pycryptodome
```

### 2. Start the Backend
```bash
python app.py
```
The Flask server runs on **http://localhost:5000**

### 3. Open the Frontend
Open `index.html` in any modern browser.

> ⚠ Make sure `app.py` is running BEFORE using the web app.

---

## Encryption Techniques Used

### 1. Caesar Cipher (ROT-13)
- **Type:** Classical Substitution Cipher
- **How it works:** Shifts each letter by 13 positions in the alphabet (A→N, B→O…). Since 13 × 2 = 26, encrypting twice returns the original — making it self-inverse.
- **Key:** Shift = 13 (fixed)
- **Strength:** Very weak — trivially broken by frequency analysis. Included for educational/historical value.

### 2. AES-256 (Advanced Encryption Standard)
- **Type:** Modern Symmetric Block Cipher
- **Mode:** CBC (Cipher Block Chaining) with a random 16-byte IV per encryption
- **Key Length:** 256 bits (32 bytes)
- **How it works:** Divides plaintext into 128-bit blocks, applies 14 rounds of SubBytes, ShiftRows, MixColumns, and AddRoundKey transformations. CBC mode XORs each block with the previous ciphertext before encryption.
- **Strength:** Industry standard. AES-256 has never been broken in practice.
- **Library:** `PyCryptodome`

### 3. DES (Data Encryption Standard)
- **Type:** Legacy Symmetric Block Cipher
- **Mode:** CBC with a random 8-byte IV per encryption
- **Key Length:** 64 bits (8 bytes, only 56 effective bits)
- **How it works:** 16 rounds of Feistel network operations — expansion, XOR with subkey, S-box substitution, and permutation.
- **Strength:** Considered weak today; key space (2^56) is brute-forceable. Included for educational purposes.
- **Library:** `PyCryptodome`

### 4. RSA-2048 (Rivest–Shamir–Adleman)
- **Type:** Asymmetric Public-Key Cipher
- **Padding:** OAEP (Optimal Asymmetric Encryption Padding)
- **How it works:** Uses mathematical properties of large prime numbers. A public key encrypts; only the corresponding private key can decrypt.
- **Strength:** Widely used for key exchange and digital signatures. 2048-bit keys are currently considered secure.
- **Note:** Input limited to ≤190 bytes due to RSA block size constraints.
- **Library:** `PyCryptodome`

### 5. Base64 (Encoding)
- **Type:** Binary-to-text encoding (NOT true encryption)
- **How it works:** Converts binary data to ASCII using a 64-character alphabet. Every 3 bytes become 4 Base64 characters.
- **Strength:** Trivially reversible — provides no security. Useful for safe transmission of binary data.

### 6. SHA-256 (Secure Hash Algorithm)
- **Type:** Cryptographic Hash Function (one-way)
- **Output:** 256-bit (64-character hex) digest
- **How it works:** Processes input through compression rounds producing a fixed-length fingerprint. A single bit change in input completely changes the output (avalanche effect).
- **Use Cases:** Password storage, data integrity verification, digital signatures.
- **Strength:** No known collision attacks. Cannot be reversed.
- **Library:** Python built-in `hashlib`

---

## Features Implemented

| Feature                    | Status |
|----------------------------|--------|
| Encrypt text               | ✅     |
| Decrypt text               | ✅     |
| ≥3 encryption algorithms   | ✅ (5) |
| Empty input validation     | ✅     |
| Algorithm selection check  | ✅     |
| SHA-256 hashing (bonus)    | ✅     |
| Copy ciphertext (bonus)    | ✅     |
| Decryption feature (bonus) | ✅     |

---

## Tech Stack
- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **Backend:** Python 3 · Flask · Flask-CORS
- **Encryption:** PyCryptodome · Python `hashlib`
- **Fonts:** Google Fonts (Orbitron, Rajdhani, Share Tech Mono)
