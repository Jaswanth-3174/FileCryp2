from flask import Flask, render_template, request, send_from_directory
from werkzeug.utils import secure_filename
from web3 import Web3
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64decode
from io import BytesIO
import gzip
from py7zr import SevenZipFile
import os
import random
import string
from datetime import datetime
import requests
import compression
import ipfs_blockchain
import secrets
from compression import compress_and_pin_to_ipfs
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Connect to the local Ethereum node
w3 = Web3(Web3.HTTPProvider('http://localhost:7545'))

def generate_random_string(length=16):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return random_string

def get_file_info(file_paths):
    # Assume compress_and_pin_to_ipfs is defined somewhere
    compressed_file_path, ipfs_hash, encrypted_hash, transaction_hash = compress_and_pin_to_ipfs(file_paths)

    return {
        'file_name': os.path.basename(compressed_file_path),
        'ipfs_hash': ipfs_hash,
        'encrypted_hash': encrypted_hash,
        'transaction_hash': transaction_hash
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'files[]' not in request.files:
        return "No file part"

    files = request.files.getlist('files[]')

    if not files:
        return "No selected files"

    sanitized_filenames = []

    for file in files:
        filename = secure_filename(file.filename)
        sanitized_filenames.append(filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

    file_info = get_file_info([os.path.join(app.config['UPLOAD_FOLDER'], f) for f in sanitized_filenames])

    for file_path in [os.path.join(app.config['UPLOAD_FOLDER'], f) for f in sanitized_filenames]:
        os.remove(file_path)

    return render_template('upload_success.html', file_info=file_info)

@app.route('/upload_page')
def upload_page():
    return render_template('das.html')

@app.route('/uploadFiles.html')
def upload_files():
    return render_template('uploadFiles.html')

@app.route('/downloadPage')
def download_page():
    return render_template('downloadPage.html')  # Assuming you have a downloadPage.html template

@app.route('/process_transaction', methods=['POST'])
def process_transaction_from_download_page():
    try:
        tx_hash = request.form['tx_hash']
        return redirect(url_for('process_transaction', tx_hash=tx_hash))
    except Exception as e:
        error_message = f"Error: {e}"
        return render_template('error.html', error_message=error_message)

@app.route('/process_transaction/<tx_hash>')
def process_transaction(tx_hash):
    try:
        tx_details = w3.eth.get_transaction(tx_hash)
        binary_data = tx_details['input']
        hex_representation = ''.join([f'{byte:02x}' for byte in binary_data])

        contract_address = '0xe1F5A0215d04E5c0F59D9000523366DeDBF21729'
        contract_abi =  [
        {
            "inputs": [
                {
                    "internalType": "string",
                    "name": "hash",
                    "type": "string"
                }
            ],
            "name": "storeHash",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "getStoredHash",
            "outputs": [
                {
                    "internalType": "string",
                    "name": "",
                    "type": "string"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "storedHash",
            "outputs": [
                {
                    "internalType": "string",
                    "name": "",
                    "type": "string"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        }
    ]
        contract = w3.eth.contract(address=contract_address, abi=contract_abi)

        tx_data_hex = hex_representation
        tx_data_bytes = bytes.fromhex(tx_data_hex)

        decoded_input = contract.decode_function_input(tx_data_bytes)
        hash_value = decoded_input[1]['hash']

        password = "supersecretpassword"
        decrypted_text = decrypt(hash_value, password)
#Change target directory as per system
        target_directory = r'D:\FileCryp download files'
        extracted_folder = download_and_decompress_ipfs_file(decrypted_text, target_directory)

        return render_template('result.html', tx_details=tx_details, hash_value=hash_value, decrypted_text=decrypted_text, extracted_folder=extracted_folder)
    except Exception as e:
        error_message = f"Error: {e}"
        return render_template('error.html', error_message=error_message)

def decrypt(cipher_text, password):
    full_cipher = urlsafe_b64decode(cipher_text)
    salt = full_cipher[:16]
    iv = full_cipher[16:32]
    cipher_text = full_cipher[32:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(cipher_text) + decryptor.finalize()
    return decrypted_text.decode()

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=16
    )
    return kdf.derive(password.encode())

def generate_random_string(length=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))

def generate_filename(hash_value):
    random_string = generate_random_string()
    hash_start = hash_value[:4]
    current_time = datetime.now().strftime("%Y%m%d%H%M%S")
    hash_end = hash_value[-4:]
    filename = f'{random_string}_{hash_start}_{current_time}_{hash_end}'
    return filename

def download_and_decompress_ipfs_file(hash_value, target_directory):
    url = f'https://ipfs.io/ipfs/{hash_value}'
    response = requests.get(url)
    content_type = response.headers.get('Content-Type')

    if 'gzip' in content_type:
        with gzip.GzipFile(fileobj=BytesIO(response.content)) as f:
            file_data = f.read()
    else:
        file_data = response.content

    temp_filename = generate_filename(hash_value)
    temp_file_path = os.path.join(target_directory, f'{temp_filename}.7z')

    with open(temp_file_path, 'wb') as f:
        f.write(file_data)

    decompress_folder = os.path.join(target_directory, generate_filename(hash_value))
    decompress_file(temp_file_path, decompress_folder)

    # Remove the original 7z file after decompression
    os.remove(temp_file_path)

    return decompress_folder

def decompress_file(compressed_file_path, extract_folder):
    with SevenZipFile(compressed_file_path, 'r') as archive:
        archive.extractall(extract_folder)

if __name__ == '__main__':
    app.run(debug=True)
