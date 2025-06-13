
from auth.kerberos import Kerberos
from crypto.aes_hmac import AESCipher
from logging_sys.hash_logger import HashLogger
from utils.helpers import generate_keys
import os
def main():
    print("=== Secure Transmission System ===")
    
    # Read inputs from file
    with open("input.txt", "r") as f:
        lines = f.readlines()
        client_id = lines[0].strip().encode()
        message = lines[1].strip().encode()


    # Step 1: Simulate Kerberos Ticket Generation
    shared_key = os.urandom(32)
    kerberos = Kerberos(shared_key)
    ticket = kerberos.generate_ticket(client_id)
    print("Kerberos ticket issued.")

    # Step 2: Encrypt message with AES-CBC + HMAC
    key, hmac_key = generate_keys()
    cipher = AESCipher(key, hmac_key)
    ciphertext = cipher.encrypt(message)
    print("Message encrypted securely.")

    # Step 3: Tamper-evident logging
    logger = HashLogger()
    logger.log(f"Encrypted message from {client_id.decode()}")
    print("Action logged securely.")

    # Optional: decrypt to verify
    print("Decrypting to verify...")
    print("Decrypted:", cipher.decrypt(ciphertext).decode())

if __name__ == "__main__":
    main()
