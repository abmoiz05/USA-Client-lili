import os
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

backup_dir = "full_backup"
incremental_dir = "incremental_backup"
encrypted_dir = "encrypted_backup"
key_file = "encryption.key"

os.makedirs(backup_dir, exist_ok=True)
os.makedirs(incremental_dir, exist_ok=True)
os.makedirs(encrypted_dir, exist_ok=True)

def generate_key():
    key = get_random_bytes(32)  # 256-bit key
    with open(key_file, "wb") as f:
        f.write(key)
    return key

def load_key():
    if not os.path.exists(key_file):
        return generate_key()
    with open(key_file, "rb") as f:
        return f.read()

def encrypt_file(file_path, output_path, key):
    with open(file_path, "rb") as f:
        data = f.read()

    nonce = get_random_bytes(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    aad = b"Backup_Header"
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(output_path, "wb") as f:
        f.write(nonce + tag + ciphertext)

def encrypt_folder(folder_path, output_base, key):
    if not os.path.exists(output_base):
        os.makedirs(output_base)

    for filename in os.listdir(folder_path):
        source = os.path.join(folder_path, filename)
        if os.path.isfile(source):
            target = os.path.join(output_base, filename + ".enc")
            encrypt_file(source, target, key)

key = load_key()
encrypt_folder(backup_dir, os.path.join(encrypted_dir, "full"), key)
encrypt_folder(incremental_dir, os.path.join(encrypted_dir, "incremental"), key)

print("Full and incremental backup encryption complete.")
print(f"Encrypted files saved to: {encrypted_dir}/full and {encrypted_dir}/incremental")
