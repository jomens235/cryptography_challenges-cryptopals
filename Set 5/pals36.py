from random import randint
from hashlib import sha256
from pals33 import modular_pow
from pals34 import xor_data
from requests import post


# Set 5 Challenge 36
BASE_URL = "http://127.0.0.1:5000/"

# Generated using openssl
N = int("008c5f8a80af99a7db03599f8dae8fb2f75b52501ef54a827b8a1a586f14dfb20d6b5e2ff878b9ad6bca0bb9"
        "18d30431fca1770760aa48be455cf5b949f3b86aa85a2573769e6c598f8d902cc1a0971a92e55b6e04c4d07e"
        "01ac1fa9bdefd1f04f95f197b000486c43917568ff58fafbffe12bde0c7e8f019fa1cb2b8e1bcb1f33", 16)

# Client + server agree on these vals beforehand
g = 2
k = 3
I = 'jstanfield@live.esu.edu'
P = "randP@ssw0rd"
a = randint(0, N - 1)

# Based off of Wikipedia pseudo-code, returns HMAC-SHA256 for key + msg
def hmac_sha256(key, message):
    """Returns the HMAC-SHA256 for the given key and message. Written following Wikipedia pseudo-code."""
    if len(key) > 64:
        key = sha256(key).digest()
    if len(key) < 64:
        key += b'\x00' * (64 - len(key))

    o_key_pad = xor_data(b'\x5c' * 64, key)
    i_key_pad = xor_data(b'\x36' * 64, key)

    return sha256(o_key_pad + sha256(i_key_pad + message).digest()).hexdigest()

# Gets SHA1 hash of input, returns int related to output
def h(data):
    return int(sha256(data.encode()).hexdigest(), 16)

# Secure Remote Password implementation on client site
def srp():
    # Generate A from DH
    A = modular_pow(g, a, N)
    response = post(BASE_URL, json={'I': I, 'A': A}).json()

    # Get B & salt from server
    salt = response.get('salt')
    B = response.get('B')

    # Generate u
    u = h(str(A) + str(B))

    # Client processing
    x = h(salt + P)
    S = modular_pow(B - k * modular_pow(g, x, N), a + u * x, N)
    K = sha256(str(S).encode()).digest()

    # Compute HMAC
    hm = hmac_sha256(K, salt.encode())

    # Get verification from server
    response = post(BASE_URL, json={'hm': hm}).text
    return response


# Main Function
if __name__ == '__main__':
    """CryptoPals Set 5 #36"""
    outcome = srp()
    print(srp())

    # Check that it works
    assert outcome == "OK"
    # Doesn't print if assertion fails
    print("Implementation Works!")
