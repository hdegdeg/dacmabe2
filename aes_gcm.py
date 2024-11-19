import sys
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

data = 'secret data to transmit'.encode()

aes_key = get_random_bytes(16)

# Numéro de session
session_id = 123456789

# Transformation du numéro de session en nonce de 15 octets
nonce = session_id.to_bytes(15, byteorder='big', signed=False)

# Initialisation du chiffrement AES en mode OCB
cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

ciphertext, tag = cipher.encrypt_and_digest(data)
#assert len(cipher.nonce) == 15

 

 # Numéro de session
session_id = 123456789

# Transformation du numéro de session en nonce de 15 octets
nonce = session_id.to_bytes(15, byteorder='big', signed=False)
#nonce =  cipher.nonce

cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
try:
    message = cipher.decrypt_and_verify(ciphertext, tag)
    print(message)
except ValueError:
    print("The message was modified!")
    sys.exit(1)