
import os, hmac, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class AESCipher:
    def __init__(self, key, hmac_key):
        self.key = key
        self.hmac_key = hmac_key

    def encrypt(self, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        pad_len = 16 - len(plaintext) % 16
        padded = plaintext + bytes([pad_len] * pad_len)
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        tag = hmac.new(self.hmac_key, iv + ciphertext, hashlib.sha256).digest()
        return iv + ciphertext + tag

    def decrypt(self, data):
        iv, ciphertext, tag = data[:16], data[16:-32], data[-32:]
        if not hmac.compare_digest(hmac.new(self.hmac_key, iv + ciphertext, hashlib.sha256).digest(), tag):
            raise ValueError("Integrity check failed!")
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        pad_len = padded[-1]
        return padded[:-pad_len]
