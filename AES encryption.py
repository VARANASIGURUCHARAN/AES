from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    
    # Padding the plaintext before encryption
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size)

    ciphertext = cipher.encrypt(padded_data)
    return b64encode(cipher.iv + ciphertext)

def aes_decrypt(key, ciphertext):
    data = b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv=data[:AES.block_size])
    
    decrypted_data = unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size)
    return decrypted_data.decode('utf-8')

# Take user input for key and plaintext
key = input("Enter the key (16, 24, or 32 bytes): ").encode('utf-8')
plaintext = input("Enter the plaintext: ")

# Encryption
encrypted_text = aes_encrypt(key, plaintext)
print("Encrypted:", encrypted_text.decode('utf-8'))

# Decryption
decrypted_text = aes_decrypt(key, encrypted_text)
print("Decrypted:", decrypted_text)
