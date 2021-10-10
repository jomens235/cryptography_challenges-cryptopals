from random import randint
from hashlib import sha256
from pals33 import modular_pow
from requests import post
from pals36 import hmac_sha256, h


# Set 5 Challenge 38
BASE_URL = "http://127.0.0.1:5000/"

# Made with OpenSLL
N = int("008c5f8a80af99a7db03599f8dae8fb2f75b52501ef54a827b8a1a586f14dfb20d6b5e2ff878b9ad6bca0bb918d30431fca1770760aa4"
        "8be455cf5b949f3b86aa85a2573769e6c598f8d902cc1a0971a92e55b6e04c4d07e01ac1fa9bdefd1f04f95f197b000486c43917568ff"
        "58fafbffe12bde0c7e8f019fa1cb2b8e1bcb1f33", 16)

# Client & server check these
g = 2
k = 3
I = 'jstanfield@live.esu.edu'
# Earlyish word in the list of 10,000 words referenced in server
P = "baseball"
a = randint(0, N - 1)


# Secure Remote Password for client
def simple_srp():
    # Generate A from DH
    A = modular_pow(g, a, N)
    response = post(BASE_URL, json={'I': I, 'A': A}).json()

    # Get B & salt from server
    salt = response.get('salt')
    B = response.get('B')

    # Generate u
    u = h(str(A) + str(B))

    # Do client processing
    x = h(salt + P)
    S = modular_pow(B, a + u * x, N)
    K = sha256(str(S).encode()).digest()

    # Compute HMAC
    hm = hmac_sha256(K, salt.encode())

    # Get verification from server
    response = post(BASE_URL, json={'hm': hm}).text
    return response


# Main Function
if __name__ == '__main__':
    """CryptoPals Set 5 #38"""
    outcome = simple_srp()

    # Make sure program ran w/o errors
    assert outcome == "OK"
    print("Attack succeeded.")
