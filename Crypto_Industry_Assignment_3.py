import os
import hashlib
import hmac
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

firmware_file = "server_firmware.bin"
downloaded_file = "downloaded_firmware.bin"
encrypted_file = "firmware_encrypted.bin"
key_file = "secure_key.bin"

firmware_data = b"VERSION=2.1.3\nPATCH=Security Update\nCRC=0xAABBCCDD\n"
with open(firmware_file, "wb") as f:
    f.write(firmware_data)

def get_or_generate_key():
    if not os.path.exists(key_file):
        key = get_random_bytes(32)  # 256-bit key
        with open(key_file, "wb") as f:
            f.write(key)
    else:
        with open(key_file, "rb") as f:
            key = f.read()
    return key

key = get_or_generate_key()

def encrypt_firmware(input_path, output_path, key):
    with open(input_path, "rb") as f:
        data = f.read()

    nonce = get_random_bytes(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    aad = b"Firmware_Header_v1"
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(output_path, "wb") as f:
        f.write(nonce + tag + ciphertext)

    return aad, nonce

aad, nonce = encrypt_firmware(firmware_file, encrypted_file, key)

def decrypt_firmware(encrypted_path, output_path, key, nonce, aad):
    with open(encrypted_path, "rb") as f:
        raw = f.read()

    tag = raw[12:28]
    ciphertext = raw[28:]

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)

    with open(output_path, "wb") as f:
        f.write(decrypted)

decrypt_firmware(encrypted_file, downloaded_file, key, nonce, aad)

def compute_hmac(file_path, key):
    with open(file_path, "rb") as f:
        data = f.read()
    return hmac.new(key, data, hashlib.sha256).hexdigest()

original_mac = compute_hmac(firmware_file, key)
downloaded_mac = compute_hmac(downloaded_file, key)

if hmac.compare_digest(original_mac, downloaded_mac):
    print("Firmware downloaded successfully and verified.")
    print(f"HMAC: {original_mac}")
else:
    print(" Integrity check failed. Do not install firmware.")
