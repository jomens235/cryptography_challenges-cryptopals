from random import randint
from Cryptodome import Random
import struct
from pals23 import MT19937

# Function from several challenges ago
def xor_data(bin_data_1, bin_data_2):
    return bytes([b1 ^ b2 for b1, b2 in zip(bin_data_1, bin_data_2)])

# Class similar to the previous MT19937 cipher class
class MT19937Cipher:
    def __init__(self, key):
        self._rng = MT19937(key)

    # Uses MT19937 PRNG to make a keystream of the bytes, then XORs it with pt
    def encrypt(self, plaintext):
        keystream = b''

        while len(keystream) < len(plaintext):
            keystream += struct.pack('>L', self._rng.extract_number())
        return xor_data(plaintext, keystream)

    # Same as encryption
    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)

# Brute forces all possible 16 bit seeds
def find_mt19937_stream_cipher_key(ciphertext, known_plaintext):
    print("Brute-forcing possible seeds...")
    for guessed_seed in range(2**16):
        candidate = MT19937Cipher(guessed_seed).decrypt(ciphertext)

        if known_plaintext in candidate:
            print("Seed found:", guessed_seed)
            return guessed_seed

    # If this happens it wasn't a 16-bit num
    raise Exception("The seed was not a 16 bit number")

if __name__ == '__main__':
    # Generate a random seed for key
    seed = randint(0, 2 ** 16 - 1)

    # Generate plaintext to encrypt for the password token
    random_prefix = Random.new().read(randint(0, 100)) + b';'
    known_plaintext = b'jwstanfield'
    random_suffix = b';' + b'password_reset=true'

    ciphertext = MT19937Cipher(seed).encrypt(random_prefix + known_plaintext + random_suffix)
    guessed_seed = find_mt19937_stream_cipher_key(ciphertext, known_plaintext)

    # Make sure the seeds are the same
    assert guessed_seed == seed
    print("Decrypted password reset plaintext:", MT19937Cipher(seed).encrypt(ciphertext))
