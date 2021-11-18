from Cryptodome.Hash import SHA3_256
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
import sys
import os
import errno
def clear_files(a, b, c):
    if os.path.exists("../public/" + str(a)):
        os.remove("../public/" + str(a))
    
    if os.path.exists("../public/" + str(b)):
        os.remove("../public/" + str(b))
    
    if os.path.exists(str(c)):
        os.remove(str(c))
    

def generate_public_and_private_keys(public_key_name, private_key_name):
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open(str(private_key_name), "+wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    try:
        os.makedirs("../public/")
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
    file_out = open("../public/" + str(public_key_name), "+wb")
    file_out.write(public_key)
    file_out.close()
    print(str(public_key_name) + " and " + str(private_key_name) + " were generated!")
    return public_key, private_key

def generate_sha3_256_hash():
    while True:
        try:
            filename = input("Enter the input file name: ")
            hash = SHA3_256.new()
            with open(filename, "rb") as f:
                # Read and update hash string value in blocks of 4KB
                for byte_block in iter(lambda: f.read(4096), b""):
                    hash.update(byte_block)
                print("Hash: " + str(hash.hexdigest()))
                break
        except Exception as e:
            #Catch all exceptions and print it
            print(e)
    return hash

def write_encrypted_file(hash, encrypted_filename, public_key_name):
    data = hash.hexdigest().encode("utf-8")
    print("Waiting for public key...")
    while True:
        try:
            recipient_key = RSA.import_key(open("../public/" + str(public_key_name)).read())
            break
        except:
            pass
    print("Public key loaded!")
    

    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key and generate an authentication tag
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    
    try:
        #Write the file contents
        file_out = open("../public/" + str(encrypted_filename), "+wb")
        [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    except:
        print("Something happened while writing the encrypted file!")
        print("Halting...")
        sys.exit(1)
    
    print("Encrypted file exported!")
    file_out.close()

def write_encrypted_file_silent(hash, encrypted_filename, public_key_name):
    data = hash.hexdigest().encode("utf-8")
    # print("Waiting for public key...")
    while True:
        try:
            recipient_key = RSA.import_key(open("../public/" + str(public_key_name)).read())
            break
        except:
            pass
    # print("Public key loaded!")
    

    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key and generate an authentication tag
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    
    try:
        #Write the file contents
        file_out = open("../public/" + str(encrypted_filename), "+wb")
        [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    except:
        print("Something happened while writing the encrypted file!")
        print("Halting...")
        sys.exit(1)
    
    # print("Encrypted file exported!")
    file_out.close()

def decrypt_and_compare(hash, encrypted_filename, private_key):
    private_key = RSA.import_key(private_key)
    print("Opening encrypted message...")
    while True:
        try:
            file_in = open("../public/" + str(encrypted_filename), "rb")
            break
        except:
            pass
    
    try:
        #Read the file contents
        enc_session_key, nonce, tag, ciphertext = \
            [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
    except Exception as e:
        print(e)
        print("Something happened while reading the encrypted file!")
        print("Halting...")
        sys.exit(1)
    
    print("Encrypted message loaded!")

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print("Your file:" + hash.hexdigest())
    print("Their file: " + data.decode("utf-8"))
    if (data.decode("utf-8") == hash.hexdigest()):
        print("The two files are the identical.")
    else:
        print("The two files are different.")