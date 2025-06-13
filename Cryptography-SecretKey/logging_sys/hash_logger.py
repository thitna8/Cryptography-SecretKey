
import hashlib

class HashLogger:
    def __init__(self, log_file='secure.log'):
        self.log_file = log_file
        self.last_hash = '0' * 64

    def log(self, message):
        entry = f"{message}|{self.last_hash}"
        current_hash = hashlib.sha256(entry.encode()).hexdigest()
        with open(self.log_file, 'a') as f:
            f.write(f"{message}|{self.last_hash}|{current_hash}\n")
        self.last_hash = current_hash
