from time import sleep
from pals28 import sha1
from pals25 import fixed_xor
from binascii import unhexlify
from flask import Flask

key = b"YELLOW_SUBMARINE"
delay = 0     # Change depending on the challenge

# Set 4 Challenge 31 Web file
# Based off of Wikipedia pseudo-code again
def hmac_sha1(key, message):
    if len(key) > 64:
        key = unhexlify(sha1(key))
    if len(key) < 64:
        key += b'\x00' * (64 - len(key))

    o_key_pad = fixed_xor(b'\x5c' * 64, key)
    i_key_pad = fixed_xor(b'\x36' * 64, key)

    return sha1(o_key_pad + unhexlify(sha1(i_key_pad + message)))

# Does byte at a time comparisons with ==, sleeps 50ms after each byte
def insecure_equals(s1, s2):
    for b1, b2 in zip(s1, s2):
        if b1 != b2:
            return False
        sleep(delay)
    return True

# Use Flask as web server
app = Flask(__name__)


if __name__ == '__main__':
    """CryptoPals Set 4 #31 Web"""
    # Starts Flask
    app.run(port=8082)
