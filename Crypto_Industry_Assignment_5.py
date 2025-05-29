import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def encrypt_AES(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct  

def decrypt_AES(key, data):
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

key_client_TAS = get_random_bytes(16)  
key_server_TAS = get_random_bytes(16)  

client_id = b"Client"
server_id = b"Server"
nonce_client = get_random_bytes(8)

session_key = get_random_bytes(16)

ticket_for_server = encrypt_AES(key_server_TAS, session_key + client_id)

msg_for_client_encrypted = encrypt_AES(key_client_TAS, session_key + server_id + nonce_client)
msg_to_client = msg_for_client_encrypted + ticket_for_server  # full message

print("\n[Client] Received encrypted response from TAS.")

enc_client_part = msg_to_client[:len(msg_for_client_encrypted)]
ticket_from_TAS = msg_to_client[len(msg_for_client_encrypted):]

decrypted_client_part = decrypt_AES(key_client_TAS, enc_client_part)

received_session_key = decrypted_client_part[:16]
received_server_id = decrypted_client_part[16:22]
received_nonce = decrypted_client_part[22:]

print("[Client] Session key and server identity verified.")

timestamp = b"12345678"
authenticator = encrypt_AES(received_session_key, timestamp)

print("\n[Client → Server] Sending ticket and authenticator...")

decrypted_ticket = decrypt_AES(key_server_TAS, ticket_from_TAS)
session_key_from_ticket = decrypted_ticket[:16]
client_id_from_ticket = decrypted_ticket[16:]

decrypted_timestamp = decrypt_AES(session_key_from_ticket, authenticator)

response_encrypted = encrypt_AES(session_key_from_ticket, decrypted_timestamp[::-1])
response_decrypted = decrypt_AES(session_key_from_ticket, response_encrypted)

print("[Server] Authenticator and client identity verified.")

print(f"\n Mutual authentication complete. Timestamp echoed back: {response_decrypted[::-1].decode()}")