
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, time

class Kerberos:
    def __init__(self, shared_key):
        self.shared_key = shared_key

    def generate_ticket(self, client_id):
        timestamp = str(int(time.time())).encode()
        ticket = f"{client_id.decode()}||{timestamp.decode()}".encode()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.shared_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padded = ticket + b' ' * (16 - len(ticket) % 16)
        return iv + encryptor.update(padded) + encryptor.finalize()
