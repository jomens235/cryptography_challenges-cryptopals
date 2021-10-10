import struct
from random import randint
from binascii import unhexlify
from pals28 import sha1
import requests

# Set 4 Challenge 29
# Website containing list of words to generate key from
word_site = "https://www.mit.edu/~ecprice/wordlist.10000"
response = requests.get(word_site)
WORDS = response.content.splitlines()

class Oracle:

    def __init__(self):
        # Get random word from online list of 10,000 words
        self._key = WORDS[randint(0,10000)]

    def validate(self, message, digest):
        # Check if digest matches keyed SHA1 MAC
        return sha1(self._key + message) == digest

    def generate_digest(self, message):
        # Generate SHA1 MAC digest w/ secret key
        return sha1(self._key + message)


def md_pad(message):
    # Pads input message same way as SHA1 algorithm
    ml = len(message) * 8
    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'

    message += struct.pack('>Q', ml)
    return message

# Does a length extension attack on SHA1 keyed MAC
def length_extension_attack(message, original_digest, oracle):
    extra_payload = b';admin=true'

    # Try multiple key lengths
    for key_length in range(100):
        # Get forged message
        forged_message = md_pad(b'A' * key_length + message)[key_length:] + extra_payload

        # Get SHA1 internal state by undoing last step of hash
        h = struct.unpack('>5I', unhexlify(original_digest))

        # Compute the SHA1 hash of extra payload
        forged_digest = sha1(extra_payload, (key_length + len(forged_message)) * 8, h[0], h[1], h[2], h[3], h[4])

        # If forged digest is valid, return it together with forged message
        if oracle.validate(forged_message, forged_digest):
            return forged_message, forged_digest

    # If key length was not guessed properly
    raise Exception("Not possible to forge the message: maybe the key was longer than 100 characters.")

# Main function
if __name__ == '__main__':
    """CryptoPals Set 4 #29"""
    oracle = Oracle()

    # Compute original digest of given message
    message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    message_digest = oracle.generate_digest(message)

    # Forge a variant of this message and get its valid MAC
    forged_message, forged_digest = length_extension_attack(message, message_digest, oracle)

    # Check if attack works
    assert b';admin=true' in forged_message
    assert oracle.validate(forged_message, forged_digest)
    print("Both assertions are true, meaning it worked.")
