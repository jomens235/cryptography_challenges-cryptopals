from pals33 import modular_pow
from pals36 import hmac_sha256, h
from flask import Flask, request, jsonify
from hashlib import sha256
from random import randint


# Set 5 Challenge 36 Server
# Generated using openssl
N = int("008c5f8a80af99a7db03599f8dae8fb2f75b52501ef54a827b8a1a586f14dfb20d6b5e2ff878b9ad6bca0bb9"
        "18d30431fca1770760aa48be455cf5b949f3b86aa85a2573769e6c598f8d902cc1a0971a92e55b6e04c4d07e"
        "01ac1fa9bdefd1f04f95f197b000486c43917568ff58fafbffe12bde0c7e8f019fa1cb2b8e1bcb1f33", 16)

# Client + server agree on these vals beforehand
g = 2
k = 3

# Password database simulated
passwords = {'jstanfield@live.esu.edu': "randP@ssw0rd"}

# Server computes vals on its own
b = randint(0, N - 1)
salt = str(randint(0, 2**32 - 1))

# Values to update
v = None
A, B = None, None
S, K = None, None

app = Flask(__name__)


@app.route('/', methods=['POST'])
def login():
    global v, A, B, S, K

    # Only HTTP POST reqs
    if request.method == 'POST':

        # Get data sent by client as json
        post_data = request.get_json()

        # If in the first (C->S) post
        if 'I' in post_data and 'A' in post_data:

            # Get I & A sent by client
            I = post_data.get('I')
            A = post_data.get('A')

            # Find from database, password of the client, compute v from it
            P = passwords[I]
            v = modular_pow(g, h(salt + P), N)

            # Compute B & u
            B = (k * v + modular_pow(g, b, N)) % N
            u = h(str(A) + str(B))

            # Compute S & K
            S = modular_pow(A * modular_pow(v, u, N), b, N)
            K = sha256(str(S).encode()).digest()

            # Send user salt & B (first S->C)
            return jsonify(salt=salt, B=B)

        # If in second (C->S) post
        elif 'hm' in post_data:

            # Get client HMAC
            hm = post_data.get('hm')

            # Compute server HMAC
            my_hm = hmac_sha256(K, salt.encode())

            # Tell user if they match (second S->C)
            if hm == my_hm:
                return "OK", 200
            else:
                return "BAD", 500


# Main Function
if __name__ == '__main__':
    """CryptoPals Set 5 #36 Server"""
    app.run()