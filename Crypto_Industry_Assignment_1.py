# Cryptography Industry Assignment 1
# Design AEAD using ECC (Elliptic Curve Cryptography) with ChaCha20-Poly1305 AEAD mode

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

# -------------------- Step 1: Key Generation --------------------
# Generate ECC private and public key pairs for both sender and receiver
sender_private_key = ec.generate_private_key(ec.SECP256R1())
sender_public_key = sender_private_key.public_key()

receiver_private_key = ec.generate_private_key(ec.SECP256R1())
receiver_public_key = receiver_private_key.public_key()

# -------------------- Step 2: Key Exchange (ECDH) --------------------
# Sender computes shared key using its private key and receiver's public key
shared_key = sender_private_key.exchange(ec.ECDH(), receiver_public_key)

# -------------------- Step 3: Derive a Symmetric Key --------------------
# Use HKDF to derive a 256-bit key for symmetric encryption from the shared ECC key
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'AEAD Encryption Key Derivation'
).derive(shared_key)

# -------------------- Step 4: AEAD Encryption using ChaCha20-Poly1305 --------------------
# Message and AAD (Authenticated but not encrypted data)
plaintext = b"This is a confidential message."
aad = b"Header-Data-Authenticated-Only"

# Generate a random 96-bit nonce
nonce = get_random_bytes(12)

# Encrypt the message using derived symmetric key
cipher = ChaCha20_Poly1305.new(key=derived_key, nonce=nonce)
cipher.update(aad)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

print("\n--- Encryption Complete ---")
print(f"Ciphertext     : {ciphertext.hex()}")
print(f"Authentication Tag : {tag.hex()}")
print(f"Nonce          : {nonce.hex()}")

# -------------------- Step 5: AEAD Decryption --------------------
# Decrypt the message and verify its integrity
decipher = ChaCha20_Poly1305.new(key=derived_key, nonce=nonce)
decipher.update(aad)
decrypted = decipher.decrypt_and_verify(ciphertext, tag)

print("\n--- Decryption Complete ---")
print(f"Decrypted Message : {decrypted.decode()}")

# -------------------- Optional: Display ECC Public Key --------------------
# Export sender's public key (to simulate key sharing)
sender_public_bytes = sender_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print("\nSender's ECC Public Key:\n", sender_public_bytes.decode())
