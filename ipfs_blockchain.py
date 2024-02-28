# ipfs_blockchain.py
import os
import requests
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
from web3 import Web3

def pin_to_ipfs(file_path):
    api_key = "c4888a33ea19b27891c4"
    api_secret = "1b2b955d663f0ae16815dac98a9512b18e4b4c47567fed8f8128be0492d373a8"

    script_directory = os.path.dirname(os.path.abspath(__file__))
    file_path_absolute = os.path.join(script_directory, file_path)

    ipfs_url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {
        'pinata_api_key': api_key,
        'pinata_secret_api_key': api_secret
    }

    try:
        with open(file_path_absolute, "rb") as file:
            files = {'file': (os.path.basename(file_path_absolute), file)}
            response = requests.post(url=ipfs_url, headers=headers, files=files)

        if response.ok:
            ipfs_hash = response.json().get("IpfsHash")
            return ipfs_hash
        else:
            print(f"Failed to pin file to IPFS. Status code: {response.status_code}")
            print(response.text)  # Print response content for additional information
            return None
    except Exception as e:
        print(f"Error during pinning to IPFS: {e}")
        return None

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt(plain_text, password):
    salt = os.urandom(16)  # Generate a random 16-byte salt
    key = derive_key(password, salt)
    iv = os.urandom(16)  # Generate a random 16-byte IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(plain_text.encode()) + encryptor.finalize()
    return urlsafe_b64encode(salt + iv + cipher_text)

def decrypt(cipher_text, password):
    full_cipher = urlsafe_b64decode(cipher_text)
    salt = full_cipher[:16]  # Extract the salt from the ciphertext
    iv = full_cipher[16:32]  # Extract the IV from the ciphertext
    cipher_text = full_cipher[32:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(cipher_text) + decryptor.finalize()
    return decrypted_text.decode()

# ipfs_blockchain.py
from web3 import Web3

def store_hash(hash_to_store):
    try:
        ganache_url = "http://localhost:7545"
        private_key = '0x51dca82f75e5da5f2631a365033592e603ea0af9b064f70106ef4b3aad5a79be'
        account_address = '0xc57cf543b40F5E64432C692C8B3107572AE4603b'
        contract_address = '0xe1F5A0215d04E5c0F59D9000523366DeDBF21729'
        contract_abi = [
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

        web3 = Web3(Web3.HTTPProvider(ganache_url))
        contract = web3.eth.contract(address=contract_address, abi=contract_abi)

        nonce = web3.eth.get_transaction_count(account_address)
        gas_price = web3.eth.gas_price

        # Convert encrypted_hash to string before passing it to the contract function
        hash_to_store_str = hash_to_store.decode('utf-8')

        transaction = contract.functions.storeHash(hash_to_store_str).build_transaction({
            'from': account_address,
            'gas': 100000,
            'gasPrice': gas_price,
            'nonce': nonce,
        })

        signed_transaction = web3.eth.account.sign_transaction(transaction, private_key)
        transaction_hash = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)

        print(f'Transaction Hash: {transaction_hash.hex()}')
        return transaction_hash.hex()

    except Exception as e:
        print(f'Error during storing hash: {e}')
        return None


def get_stored_hash():
    ganache_url = "http://localhost:7545"
    contract_address = '0xe1F5A0215d04E5c0F59D9000523366DeDBF21729'
    contract_abi = [
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

    web3 = Web3(Web3.HTTPProvider(ganache_url))
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)

    try:
        result = contract.functions.getStoredHash().call()
        print(f'Stored Hash: {result}')
    except Exception as e:
        print(f'Error retrieving stored hash: {e}')

if __name__ == "__main__":
    # Example usage (modify file_path accordingly)
    file_path = "example.txt"
    ipfs_hash = pin_to_ipfs(file_path)

    if ipfs_hash:
        print(f"File pinned successfully to IPFS. IPFS Hash: {ipfs_hash}")

        # Example encryption and storing in blockchain
        password = "supersecretpassword"
        encrypted_hash = encrypt(ipfs_hash, password)
        print("Encrypted IPFS Hash:", encrypted_hash)

        # Example storing in Ganache blockchain
        store_hash(encrypted_hash)

        # Example retrieving stored hash from Ganache
        get_stored_hash()
    else:
        print("File pinning to IPFS failed.")
