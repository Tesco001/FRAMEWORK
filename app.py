import os
import base64
import hashlib
import hmac
import logging
import io
from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.utils import secure_filename

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'Uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload folder exists
try:
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    logger.debug(f"Created directory: {app.config['UPLOAD_FOLDER']}")
except Exception as e:
    logger.error(f"Failed to create directory: {str(e)}")

def derive_key(key_input: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Derive a 32-byte AES key from a user-provided key/password using PBKDF2HMAC."""
    logger.debug(f"Deriving key for input: {key_input[:5]}... (length: {len(key_input)})")
    if len(key_input) < 5:
        raise ValueError("Key/Password must be at least 5 characters long")
    if salt is None:
        salt = get_random_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key size
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(key_input.encode())
    return key, salt

def compute_hmac(data: bytes, key: bytes) -> bytes:
    """Compute HMAC for data integrity."""
    return hmac.new(key, data, hashlib.sha256).digest()

def encrypt_text(plain_text: str, key_input: str) -> str:
    """Encrypt text with a derived key."""
    try:
        logger.debug("Starting text encryption")
        aes_key, salt = derive_key(key_input)
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded = pad(plain_text.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded)
        hmac_value = compute_hmac(encrypted, aes_key)
        combined = salt + iv + hmac_value + encrypted
        return base64.b64encode(combined).decode()
    except Exception as e:
        logger.error(f"Text encryption failed: {str(e)}")
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_text(cipher_text: str, key_input: str) -> str:
    """Decrypt text with a derived key."""
    try:
        logger.debug("Starting text decryption")
        combined = base64.b64decode(cipher_text)
        if len(combined) < 80:
            raise ValueError("Invalid ciphertext format")
        salt, iv, stored_hmac, encrypted = combined[:16], combined[16:32], combined[32:64], combined[64:]
        aes_key, _ = derive_key(key_input, salt)
        computed_hmac = compute_hmac(encrypted, aes_key)
        if not hmac.compare_digest(stored_hmac, computed_hmac):
            raise ValueError("Incorrect key/password provided")
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        return decrypted.decode()
    except ValueError as e:
        logger.error(f"Text decryption failed: {str(e)}")
        raise ValueError(str(e))
    except Exception as e:
        logger.error(f"Text decryption failed: {str(e)}")
        raise ValueError(f"Decryption failed: {str(e)}")

def encrypt_file(file_data: bytes, filename: str, key_input: str) -> bytes:
    """Encrypt file in memory with a derived key, return processed data."""
    try:
        logger.debug(f"Encrypting file: {filename}, size: {len(file_data)} bytes")
        aes_key, salt = derive_key(key_input)
        iv = get_random_bytes(16)
        ext = os.path.splitext(filename)[1].encode()[:16].ljust(16, b'\0')
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded = pad(ext + file_data, AES.block_size)
        encrypted = cipher.encrypt(padded)
        hmac_value = compute_hmac(encrypted, aes_key)
        combined = salt + iv + hmac_value + encrypted
        logger.debug(f"File encrypted, output size: {len(combined)} bytes")
        return combined
    except Exception as e:
        logger.error(f"File encryption failed: {str(e)}")
        raise ValueError(f"File encryption failed: {str(e)}")

def decrypt_file(encrypted_data: bytes, key_input: str) -> bytes:
    """Decrypt file in memory with a derived key, return processed data."""
    try:
        logger.debug(f"Decrypting file, input size: {len(encrypted_data)} bytes")
        if len(encrypted_data) < 80:
            raise ValueError("Invalid file format")
        salt, iv, stored_hmac, encrypted = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:64], encrypted_data[64:]
        aes_key, _ = derive_key(key_input, salt)
        computed_hmac = compute_hmac(encrypted, aes_key)
        if not hmac.compare_digest(stored_hmac, computed_hmac):
            raise ValueError("Incorrect key/password provided")
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        content = decrypted[16:]  # Skip extension
        logger.debug(f"File decrypted, content size: {len(content)} bytes")
        return content
    except ValueError as e:
        logger.error(f"File decryption failed: {str(e)}")
        raise ValueError(str(e))
    except Exception as e:
        logger.error(f"File decryption failed: {str(e)}")
        raise ValueError(f"File decryption failed: {str(e)}")

@app.route('/', methods=['GET', 'POST'])
def text_encrypt_decrypt():
    result = ""
    input_text = ""
    mode = "Encrypt"
    error = ""

    if request.method == 'POST':
        input_text = request.form['text']
        key_input = request.form['key_input']
        mode = request.form['mode']
        
        if not key_input:
            error = "Key/Password is required"
        else:
            try:
                if mode == 'Encrypt':
                    result = encrypt_text(input_text, key_input)
                else:
                    result = decrypt_text(input_text, key_input)
            except Exception as e:
                error = str(e)

    return render_template('index.html', result=result, input_text=input_text, mode=mode, error=error)

@app.route('/file', methods=['GET', 'POST'])
def handle_file():
    error = ""
    success = ""

    if request.method == 'POST':
        file = request.files['file']
        key_input = request.form['key_input']
        operation = request.form['mode']
        
        if not key_input:
            error = "Key/Password is required"
        elif not file:
            error = "No file uploaded"
        else:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)  # Save uploaded file to disk
            try:
                logger.debug(f"Processing file: {filename}, operation: {operation}")
                if os.path.getsize(file_path) > app.config['MAX_CONTENT_LENGTH']:
                    raise ValueError("File size exceeds 16MB limit")
                
                # Read file and process in memory
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                
                if operation == 'Encrypt':
                    processed_data = encrypt_file(file_data, filename, key_input)
                else:
                    processed_data = decrypt_file(file_data, key_input)
                
                # Overwrite original file
                try:
                    with open(file_path, 'wb') as f:
                        f.write(processed_data)
                    logger.debug(f"File replaced: {file_path}, size: {len(processed_data)} bytes")
                    success = f"✅ File {filename} {operation.lower()}ed successfully"
                except Exception as e:
                    logger.error(f"File replacement failed: {str(e)}")
                    error = f"Failed to replace file: {str(e)}"
            except Exception as e:
                logger.error(f"File operation error: {str(e)}")
                error = str(e)

    return render_template('file.html', error=error, success=success)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)