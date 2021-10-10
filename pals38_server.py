from pals33 import modular_pow
from pals36 import hmac_sha256, h
from flask import Flask, request, jsonify
from hashlib import sha256
from random import randint
import requests


# Set 5 Challenge 38 Server
# Made with OpenSSL
N = int("008c5f8a80af99a7db03599f8dae8fb2f75b52501ef54a827b8a1a586f14dfb20d6b5e2ff878b9ad6bca0bb9"
        "18d30431fca1770760aa48be455cf5b949f3b86aa85a2573769e6c598f8d902cc1a0971a92e55b6e04c4d07e"
        "01ac1fa9bdefd1f04f95f197b000486c43917568ff58fafbffe12bde0c7e8f019fa1cb2b8e1bcb1f33", 16)

# Client & server check these
g = 2
k = 3

# Server computes these vals
b = randint(0, N - 1)
B = modular_pow(g, b, N)
salt = str(randint(0, 2**32 - 1))

# Values -> update later
v = None
A = None
S, K = None, None

app = Flask(__name__)

# MITM attack to SRP
@app.route('/', methods=['POST'])
def mitm_attack():
    global v, A, B, S, K

    if request.method == 'POST':
        # Get data sent by client as json
        post_data = request.get_json()

        # If we are in first (C->S) post:
        if 'I' in post_data and 'A' in post_data:
            # Get I & A sent by client
            I = post_data.get('I')
            A = post_data.get('A')

            # Send user salt & B (first S->C)
            return jsonify(salt=salt, B=B)

        # If we are in second (C->S) post:
        elif 'hm' in post_data:

            # Get client HMAC
            client_hm = post_data.get('hm')

            # Add words from website with 10,000 words
            with open("10kwords") as dictionary:
                candidates = dictionary.readlines()

            # Try password candidates
            for candidate in candidates:

                # Strip word
                candidate = candidate.rstrip()

                # Compute u
                u = h(str(A) + str(B))
                v = modular_pow(g, h(salt + candidate), N)

                # Compute S & K
                S = modular_pow(A * modular_pow(v, u, N), b, N)
                K = sha256(str(S).encode()).digest()

                # Compute HMAC
                candidate_hm = hmac_sha256(K, salt.encode())

                if candidate_hm == client_hm:
                    print("The password is:", candidate)
                    return "OK", 200

            return "BAD", 500


# Main Function
if __name__ == '__main__':
    """CryptoPals Set 5 #38 Server"""
    """Brute force attack, can have long delay"""
    app.run()