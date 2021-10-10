from random import randint
from hashlib import sha256
from requests import post
from pals36 import h, hmac_sha256


# Set 5 Challenge 37
BASE_URL = "http://127.0.0.1:5000/"

# Made with OpenSSL
N = int("008c5f8a80af99a7db03599f8dae8fb2f75b52501ef54a827b8a1a586f14dfb20d6b5e2ff878b9ad6bca0bb918d30431fca1770760aa4"
        "8be455cf5b949f3b86aa85a2573769e6c598f8d902cc1a0971a92e55b6e04c4d07e01ac1fa9bdefd1f04f95f197b000486c43917568ff"
        "58fafbffe12bde0c7e8f019fa1cb2b8e1bcb1f33", 16)

# Client & server make sure these are same
g = 2
k = 3
I = 'jstanfield@live.esu.edu'
a = randint(0, N - 1)

# SRP zero key attack on client: user can authenticate w/o password
def srp_zero_key():
    # Attack is done w/ 3 diff vals for A
    for A in [0, N, N * 2]:

        # Client sets A to hacking val
        response = post(BASE_URL, json={'I': I, 'A': A}).json()

        # Get salt & B from server
        salt = response.get('salt')
        B = response.get('B')

        # Generate u
        u = h(str(A) + str(B))

        # Do hacker processing
        S_c = 0
        K_c = sha256(str(S_c).encode()).digest()

        # Compute HMAC
        hm = hmac_sha256(K_c, salt.encode())

        response = post(BASE_URL, json={'hm': hm}).text
        yield response


# Main Function
if __name__ == '__main__':
    """CryptoPals Set 5 #37"""
    """This uses same server as pals36"""
    outcome = srp_zero_key()

    # Check that attack works
    # Assertion throws error if not right
    for response in outcome:
        assert response == "OK"
        print("Attack succeeded.")