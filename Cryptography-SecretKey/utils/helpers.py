
import os

def generate_keys():
    key = os.urandom(32)
    hmac_key = os.urandom(32)
    return key, hmac_key
