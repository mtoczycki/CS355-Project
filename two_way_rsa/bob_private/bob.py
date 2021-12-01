import sys
sys.path.append('../../two_way_rsa')
from utils import *
import time


hash_start_time = time.time()

hash = generate_sha3_256_hash()

hash_end_time = time.time()

public_key, private_key = generate_public_and_private_keys("bob_public_key.pem", "bob_private_key.pem")

keygen_end_time = time.time()

write_encrypted_file(hash, "bob_encrypted_msg.bin", "alice_public_key.pem")

encrypting_end_time = time.time()

while True:
    try:
        decrypt_start_time = time.time()
        decrypt_and_compare(hash, "alice_encrypted_msg.bin", private_key)
        decrypt_end_time = time.time()
        write_encrypted_file_silent(hash, "bob_encrypted_msg.bin", "alice_public_key.pem")
        break
    except ValueError as e:
        if str(e) == "Incorrect decryption.":
            print(e)
            write_encrypted_file_silent(hash, "bob_encrypted_msg.bin", "alice_public_key.pem")
        else:
            raise

clear_start_time = time.time()

clear_files("alice_encrypted_msg.bin", "alice_public_key.pem", "bob_private_key.pem")

clear_end_time = time.time()

print("Hashing took %s seconds" % (hash_end_time - hash_start_time))
print("Keygen took %s seconds" % (keygen_end_time - hash_end_time))
print("Encrypting took %s seconds" % (encrypting_end_time - keygen_end_time))
print("Decrypting took %s seconds" % (decrypt_end_time - decrypt_start_time))
print("Clearing took %s seconds" % (clear_end_time - clear_start_time))