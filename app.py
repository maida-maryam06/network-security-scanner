from flask import Flask, request, jsonify
from flask_cors import CORS
import base64
import hashlib
import json

from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

app = Flask(__name__)
CORS(app)

# ─── Caesar Cipher ───────────────────────────────────────────────
def caesar_encrypt(text, shift=13):
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)

def caesar_decrypt(text, shift=13):
    return caesar_encrypt(text, -shift)

# ─── AES (256-bit, CBC) ──────────────────────────────────────────
AES_KEY = b'InfoSecKey123456InfoSecKey123456'   # 32-byte key

def aes_encrypt(text):
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(text.encode(), AES.block_size))
    return base64.b64encode(iv + ct).decode()

def aes_decrypt(ct_b64):
    raw = base64.b64decode(ct_b64)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

# ─── DES (64-bit, CBC) ───────────────────────────────────────────
DES_KEY = b'InfoSec8'   # 8-byte key

def des_encrypt(text):
    iv = get_random_bytes(8)
    cipher = DES.new(DES_KEY, DES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(text.encode(), DES.block_size))
    return base64.b64encode(iv + ct).decode()

def des_decrypt(ct_b64):
    raw = base64.b64decode(ct_b64)
    iv, ct = raw[:8], raw[8:]
    cipher = DES.new(DES_KEY, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), DES.block_size).decode()

# ─── RSA (2048-bit) ──────────────────────────────────────────────
rsa_key  = RSA.generate(2048)
rsa_pub  = PKCS1_OAEP.new(rsa_key.publickey())
rsa_priv = PKCS1_OAEP.new(rsa_key)

def rsa_encrypt(text):
    ct = rsa_pub.encrypt(text.encode())
    return base64.b64encode(ct).decode()

def rsa_decrypt(ct_b64):
    ct = base64.b64decode(ct_b64)
    return rsa_priv.decrypt(ct).decode()

# ─── Base64 (encoding, not real encryption) ──────────────────────
def base64_encrypt(text):
    return base64.b64encode(text.encode()).decode()

def base64_decrypt(text):
    return base64.b64decode(text.encode()).decode()

# ─── SHA-256 hashing (one-way) ───────────────────────────────────
def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

# ─── Routes ──────────────────────────────────────────────────────
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    text      = data.get('text', '').strip()
    algorithm = data.get('algorithm', '')

    if not text:
        return jsonify({'error': 'Input text cannot be empty.'}), 400
    if not algorithm:
        return jsonify({'error': 'Please select an algorithm.'}), 400

    try:
        if algorithm == 'caesar':
            result = caesar_encrypt(text, shift=13)
            note   = 'ROT-13 variant (shift = 13)'
        elif algorithm == 'aes':
            result = aes_encrypt(text)
            note   = 'AES-256 CBC — output is Base64-encoded (IV prepended)'
        elif algorithm == 'des':
            result = des_encrypt(text)
            note   = 'DES-64 CBC — output is Base64-encoded (IV prepended)'
        elif algorithm == 'rsa':
            if len(text.encode()) > 190:
                return jsonify({'error': 'RSA input must be ≤ 190 characters.'}), 400
            result = rsa_encrypt(text)
            note   = 'RSA-2048 OAEP — output is Base64-encoded'
        elif algorithm == 'base64':
            result = base64_encrypt(text)
            note   = 'Base64 encoding (reversible, not truly encrypted)'
        elif algorithm == 'sha256':
            result = sha256_hash(text)
            note   = 'SHA-256 digest — one-way hash, cannot be reversed'
        else:
            return jsonify({'error': 'Unknown algorithm.'}), 400

        return jsonify({'result': result, 'note': note, 'algorithm': algorithm})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    text      = data.get('text', '').strip()
    algorithm = data.get('algorithm', '')

    if not text:
        return jsonify({'error': 'Input text cannot be empty.'}), 400
    if not algorithm:
        return jsonify({'error': 'Please select an algorithm.'}), 400
    if algorithm == 'sha256':
        return jsonify({'error': 'SHA-256 is a one-way hash and cannot be decrypted.'}), 400

    try:
        if algorithm == 'caesar':
            result = caesar_decrypt(text, shift=13)
            note   = 'Caesar Cipher decrypted (shift = 13)'
        elif algorithm == 'aes':
            result = aes_decrypt(text)
            note   = 'AES-256 CBC decrypted'
        elif algorithm == 'des':
            result = des_decrypt(text)
            note   = 'DES-64 CBC decrypted'
        elif algorithm == 'rsa':
            result = rsa_decrypt(text)
            note   = 'RSA-2048 OAEP decrypted'
        elif algorithm == 'base64':
            result = base64_decrypt(text)
            note   = 'Base64 decoded'
        else:
            return jsonify({'error': 'Unknown algorithm.'}), 400

        return jsonify({'result': result, 'note': note, 'algorithm': algorithm})

    except Exception as e:
        return jsonify({'error': 'Decryption failed — check your input and algorithm.'}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
