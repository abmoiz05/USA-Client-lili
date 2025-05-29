from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def encrypt_layer(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes  

def decrypt_layer(key, data):
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

key_R1 = get_random_bytes(16)  
key_R2 = get_random_bytes(16)  
key_B  = get_random_bytes(16)  

message = b"This is a confidential message from A to B."

layer_B = encrypt_layer(key_B, message)

layer_R2 = encrypt_layer(key_R2, layer_B)

final_packet = encrypt_layer(key_R1, layer_R2)


print("\n[Relay 1] Decrypting...")
decrypted_R1 = decrypt_layer(key_R1, final_packet)

print("[Relay 2] Decrypting...")
decrypted_R2 = decrypt_layer(key_R2, decrypted_R1)

print("[Node B] Decrypting final message...")
final_message = decrypt_layer(key_B, decrypted_R2)

print(f"\n Final message received by Node B: {final_message.decode()}")
