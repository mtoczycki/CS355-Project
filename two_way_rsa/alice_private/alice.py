import sys
sys.path.append('../../two_way_rsa')
from utils import *

hash = generate_sha3_256_hash()

public_key, private_key = generate_public_and_private_keys("alice_public_key.pem", "alice_private_key.pem")

write_encrypted_file(hash, "alice_encrypted_msg.bin", "bob_public_key.pem")

while True:
    try:
        decrypt_and_compare(hash, "bob_encrypted_msg.bin", private_key)
        write_encrypted_file_silent(hash, "alice_encrypted_msg.bin", "bob_public_key.pem")
        break
    except ValueError as e:
        if str(e) == "Incorrect decryption.":
            print(e)
            write_encrypted_file_silent(hash, "alice_encrypted_msg.bin", "bob_public_key.pem")
        else:
            raise


clear_files("bob_encrypted_msg.bin", "bob_public_key.pem", "alice_private_key.pem")

