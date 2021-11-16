from Cryptodome.PublicKey import RSA

key = RSA.generate(2048)
private_key = key.export_key()
file_out = open("private.pem", "+wb")
file_out.write(private_key)
file_out.close()

public_key = key.publickey().export_key()
file_out = open("public.pem", "+wb")
file_out.write(public_key)
file_out.close()
print("public.pem and private.pem were generated")
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
from Cryptodome.Cipher import AES, PKCS1_OAEP

file_in = open("encrypted_data.bin", "rb")

private_key = RSA.import_key(open("private.pem").read())

enc_session_key, nonce, tag, ciphertext = \
   [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

# Decrypt the session key with the private RSA key
while True:
    try:
        response = input("did the sender program finish? type \"yes\" if you are ready:");
        if(response.lower() == "yes"):
            cipher_rsa = PKCS1_OAEP.new(private_key)
            session_key = cipher_rsa.decrypt(enc_session_key)
            break;
    except FileNotFoundError:
        print("Oops!  EITHER THE MESSAGE WAS ALTERED OR THE SENDER PROGRAM DID NOT FINISH  Try again...")


# Decrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)
print(data.decode("utf-8"))
if ( data.decode("utf-8") == h.hexdigest()):
    print("THEY are the same")
else:
    print("THEY are not the same")