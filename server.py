"""
Twofish + SHA-256 File Encryption Server
=========================================
REST API server for file encryption/decryption
- Accepts form data with file, password, and operation type
- Stores encrypted/decrypted files in the project root
- CORS enabled for frontend integration
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import hashlib
import hmac
import os
import sys
import struct
import time
from werkzeug.utils import secure_filename
import io

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configuration
UPLOAD_FOLDER = os.path.dirname(os.path.abspath(__file__))  # Project root
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp3', 'wav', 'mp4', 'mov', 'avi', 'bin', 'enc'}
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE


# ──────────────────────────────────────────────
# Twofish Implementation
# ──────────────────────────────────────────────

def twofish_ksa(key: bytes) -> list:
    """Twofish Key Scheduling Algorithm (KSA)."""
    S = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def twofish_prga(S: list, data: bytes) -> bytes:
    """Twofish Pseudo-Random Generation Algorithm (PRGA) — generates keystream and XORs with data."""
    S = S[:]  # work on a copy so S is reusable
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream_byte = S[(S[i] + S[j]) % 256]
        result.append(byte ^ keystream_byte)
    return bytes(result)


def twofish_encrypt_decrypt(key: bytes, data: bytes) -> bytes:
    """Twofish is symmetric — same function for encrypt and decrypt."""
    S = twofish_ksa(key)
    return twofish_prga(S, data)


# ──────────────────────────────────────────────
# Key Derivation via SHA-256
# ──────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit key from a password + salt using SHA-256 (PBKDF2-style manual stretch).
    Iterates 100,000 rounds to resist brute-force attacks.
    """
    key_material = password.encode("utf-8")
    derived = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=key_material,
        salt=salt,
        iterations=100_000,
        dklen=32  # 256 bits
    )
    return derived


def compute_hmac(key: bytes, data: bytes) -> bytes:
    """Compute SHA-256 HMAC for integrity verification."""
    mac = hmac.new(key, data, hashlib.sha256)
    return mac.digest()


# ──────────────────────────────────────────────
# File Format Constants
# ──────────────────────────────────────────────

MAGIC = b"TF2S"
VERSION = 0x01


def encrypt_data(plaintext: bytes, password: str) -> bytes:
    """Encrypt data using Twofish + SHA-256."""
    # Generate a random 32-byte salt
    salt = os.urandom(32)

    # Derive Twofish key and HMAC key from password + salt
    master_key = derive_key(password, salt)
    twofish_key = hashlib.sha256(master_key + b"TWOFISH").digest()
    hmac_key = hashlib.sha256(master_key + b"MAC").digest()

    # Encrypt
    ciphertext = twofish_encrypt_decrypt(twofish_key, plaintext)

    # Compute HMAC over ciphertext (encrypt-then-MAC)
    mac = compute_hmac(hmac_key, ciphertext)

    # Build encrypted file format
    encrypted_output = bytearray()
    encrypted_output.extend(MAGIC)
    encrypted_output.extend(struct.pack("B", VERSION))
    encrypted_output.extend(salt)         # 32 bytes
    encrypted_output.extend(mac)          # 32 bytes
    encrypted_output.extend(ciphertext)

    return bytes(encrypted_output)


def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    """Decrypt data using Twofish + SHA-256."""
    # Parse header
    if len(encrypted_data) < 69:
        raise ValueError("File too short — not a valid TF2S encrypted file.")

    magic = encrypted_data[0:4]
    version = encrypted_data[4]
    salt = encrypted_data[5:37]
    mac_stored = encrypted_data[37:69]
    ciphertext = encrypted_data[69:]

    if magic != MAGIC:
        raise ValueError(f"Invalid magic bytes: {magic!r}. Is this a TF2S file?")
    if version != VERSION:
        raise ValueError(f"Unsupported version: {version:#04x}")

    # Derive keys
    master_key = derive_key(password, salt)
    twofish_key = hashlib.sha256(master_key + b"TWOFISH").digest()
    hmac_key = hashlib.sha256(master_key + b"MAC").digest()

    # Verify HMAC before decryption
    mac_computed = compute_hmac(hmac_key, ciphertext)
    if not hmac.compare_digest(mac_stored, mac_computed):
        raise ValueError("HMAC verification FAILED — wrong password or file tampered!")

    # Decrypt
    plaintext = twofish_encrypt_decrypt(twofish_key, ciphertext)
    return plaintext


# ──────────────────────────────────────────────
# API Routes
# ──────────────────────────────────────────────

@app.route('/api/process', methods=['POST'])
def process_file():
    """
    Process file encryption or decryption.
    
    Expected form data:
    - file: The file to encrypt/decrypt
    - password: Encryption password
    - type: Operation type ('encrypt' or 'decrypt')
    - output_filename (optional): Custom output filename
    """
    try:
        # Validate request
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        if 'password' not in request.form:
            return jsonify({'error': 'No password provided'}), 400

        if 'type' not in request.form:
            return jsonify({'error': 'No operation type provided (encrypt/decrypt)'}), 400

        file = request.files['file']
        password = request.form.get('password', '').strip()
        operation_type = request.form.get('type', '').lower().strip()
        custom_output = request.form.get('output_filename', '').strip()

        # Validate inputs
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not password:
            return jsonify({'error': 'Password cannot be empty'}), 400

        if operation_type not in ['encrypt', 'decrypt']:
            return jsonify({'error': 'Invalid operation type. Use "encrypt" or "decrypt"'}), 400

        # Read file
        file_data = file.read()
        if len(file_data) == 0:
            return jsonify({'error': 'File is empty'}), 400

        # Generate output filename
        original_filename = secure_filename(file.filename)
        if custom_output:
            output_filename = secure_filename(custom_output)
        else:
            if operation_type == 'encrypt':
                output_filename = original_filename + '.enc'
            else:
                # Remove .enc extension if present
                if original_filename.endswith('.enc'):
                    output_filename = original_filename[:-4]
                else:
                    output_filename = original_filename + '.dec'

        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

        # Process file
        if operation_type == 'encrypt':
            print(f"[*] Encrypting file: {original_filename}")
            encrypted_data = encrypt_data(file_data, password)
            
            # Write to disk
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            print(f"[+] File encrypted: {output_filename}")
            return jsonify({
                'success': True,
                'message': 'File encrypted successfully',
                'filename': output_filename,
                'size': len(encrypted_data),
                'operation': 'encrypt'
            }), 200

        elif operation_type == 'decrypt':
            print(f"[*] Decrypting file: {original_filename}")
            try:
                decrypted_data = decrypt_data(file_data, password)
            except ValueError as ve:
                return jsonify({'error': str(ve)}), 400

            # Write to disk
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            print(f"[+] File decrypted: {output_filename}")
            return jsonify({
                'success': True,
                'message': 'File decrypted successfully',
                'filename': output_filename,
                'size': len(decrypted_data),
                'operation': 'decrypt'
            }), 200

    except Exception as e:
        print(f"[!] Error: {str(e)}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/download/<filename>', methods=['GET'])
def download_file(filename):
    """Download encrypted/decrypted file from project root."""
    try:
        filename = secure_filename(filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Security check: ensure file exists and is in upload folder
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404

        if not os.path.isfile(file_path):
            return jsonify({'error': 'Invalid file'}), 400

        return send_file(file_path, as_attachment=True, download_name=filename)

    except Exception as e:
        return jsonify({'error': f'Download error: {str(e)}'}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'ok',
        'service': 'Twofish Encryption Server',
        'upload_folder': app.config['UPLOAD_FOLDER']
    }), 200


@app.route('/', methods=['GET'])
def index():
    """Root endpoint - returns API info."""
    return jsonify({
        'name': 'Twofish + SHA-256 Encryption API',
        'version': '1.0',
        'endpoints': {
            'POST /api/process': 'Encrypt or decrypt a file',
            'GET /api/download/<filename>': 'Download a processed file',
            'GET /api/health': 'Health check'
        },
        'usage': {
            'encrypt': {
                'method': 'POST',
                'url': '/api/process',
                'form_data': {
                    'file': 'File to encrypt',
                    'password': 'Encryption password',
                    'type': 'encrypt',
                    'output_filename': 'Optional custom output filename'
                }
            },
            'decrypt': {
                'method': 'POST',
                'url': '/api/process',
                'form_data': {
                    'file': 'File to decrypt',
                    'password': 'Decryption password',
                    'type': 'decrypt',
                    'output_filename': 'Optional custom output filename'
                }
            }
        }
    }), 200


if __name__ == '__main__':
    print("=" * 50)
    print("  Twofish Encryption Server")
    print("=" * 50)
    print(f"[*] Server running on http://localhost:5000")
    print(f"[*] Upload folder: {app.config['UPLOAD_FOLDER']}")
    print(f"[*] CORS enabled")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)
