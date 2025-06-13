from flask import Flask, render_template, request
from auth.kerberos import Kerberos
from crypto.aes_hmac import AESCipher
from logging_sys.hash_logger import HashLogger
from utils.helpers import generate_keys
import os

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    output = None
    if request.method == 'POST':
        client_id = request.form['client_id'].encode()
        message = request.form['message'].encode()

        # Step 1: Kerberos Ticket
        shared_key = os.urandom(32)
        kerberos = Kerberos(shared_key)
        kerberos.generate_ticket(client_id)

        # Step 2: Encryption
        key, hmac_key = generate_keys()
        cipher = AESCipher(key, hmac_key)
        ciphertext = cipher.encrypt(message)

        # Step 3: Logging
        logger = HashLogger()
        logger.log(f"Encrypted message from {client_id.decode()}")

        # Step 4: Decryption for output
        decrypted = cipher.decrypt(ciphertext).decode()

        output = {
            'ciphertext': ciphertext.hex(),
            'decrypted': decrypted
        }

    return render_template("index.html", output=output)

if __name__ == '__main__':
    app.run(debug=True)