import sys
sys.path.append('../../two_way_rsa')
from utils import *

hash = generate_sha3_256_hash()

public_key, private_key = generate_public_and_private_keys("bob_public_key.pem", "bob_private_key.pem")

write_encrypted_file(hash, "bob_encrypted_msg.bin", "alice_public_key.pem")

decrypt_and_compare(hash, "alice_encrypted_msg.bin", private_key)

clear_files("alice_encrypted_msg.bin", "alice_public_key.pem", "bob_private_key.pem")