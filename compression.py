# compression.py
from py7zr import SevenZipFile
import os
import secrets
import string
from ipfs_blockchain import pin_to_ipfs, encrypt, store_hash

def generate_random_string(length=16):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return random_string

def compress_files(files, compressed_file_path):
    with SevenZipFile(compressed_file_path, 'w') as archive:
        for file in files:
            archive.write(file, os.path.basename(file))

def decompress_file(compressed_file_path, extract_folder):
    with SevenZipFile(compressed_file_path, 'r') as archive:
        archive.extractall(extract_folder)

def compress_and_pin_to_ipfs(file_paths):
    try:
        compressed_file_path = generate_random_string() + '.7z'
        compress_files(file_paths, compressed_file_path)

        # Pin to IPFS
        ipfs_hash = pin_to_ipfs(compressed_file_path)
        if ipfs_hash:
            print(f"File pinned successfully to IPFS. IPFS Hash: {ipfs_hash}")

            # Encrypt IPFS hash
            password = "supersecretpassword"
            encrypted_hash = encrypt(ipfs_hash, password)
            print("Encrypted IPFS Hash:", encrypted_hash)

            # Store in Ganache blockchain
            transaction_hash = store_hash(encrypted_hash)

            os.remove(compressed_file_path)  # Clean up compressed file

            return compressed_file_path, ipfs_hash, encrypted_hash, transaction_hash
        else:
            print("File pinning to IPFS failed.")
            return None, None, None, None

    except Exception as e:
        print(f"Error in compress_and_pin_to_ipfs: {e}")
        return None, None, None, None
