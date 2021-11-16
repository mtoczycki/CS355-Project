
from Cryptodome.Hash import SHA3_256
# Python program to find SHA256 hash string of a file

filename = input("Enter the input file name: ")
h = SHA3_256.new()
with open(filename, "rb") as f:
    # Read and update hash string value in blocks of 4K
    for byte_block in iter(lambda: f.read(4096), b""):
        h.update(byte_block)
    print(h.hexdigest())

from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP

data = h.hexdigest().encode("utf-8")
file_out = open("encrypted_data.bin", "+wb")
while True:
    try:
        response = input("do you have the pem file? type \"yes\" if you are ready:");
        if(response.lower() == "yes"):
            recipient_key = RSA.import_key(open("public.pem").read())
            break;
    except FileNotFoundError:
        print("Oops!  YOU DO NOT HAVE THE public.pem FILE IN THE CURRENT DIRECTORY  Try again...")


session_key = get_random_bytes(16)

# Encrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_session_key = cipher_rsa.encrypt(session_key)

# Encrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)
[ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
file_out.close()