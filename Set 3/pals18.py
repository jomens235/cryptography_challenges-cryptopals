from base64 import b64decode
from Cryptodome.Cipher import AES
import random
from pals17 import aes_in_ecb_mode, fixed_xor

# Set 3 Challenge 18
BLOCK_SIZE = 16

def ctr_keystream(key: bytes, nonce: int):
    counter = 0
    nonce_bytes = nonce.to_bytes(BLOCK_SIZE // 2, byteorder='little')
    while True:
        counter_bytes = counter.to_bytes(BLOCK_SIZE // 2, byteorder='little')
        yield from aes_in_ecb_mode(nonce_bytes + counter_bytes,
                                   key, encrypt=True)
        counter += 1

def ctr_mode(byte_string: bytes, key: bytes, nonce: int) -> bytes:
    if len(byte_string) == 0:
        return b''
    return fixed_xor(byte_string, ctr_keystream(key, nonce))

# Set 3 Challenge 19
CHARACTER_FREQ = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}

# Finds out which english character is most likely to be the encoded letter w/ frequencies
def get_english_score(input_bytes):
    score = 0
    for byte in input_bytes:
        score += CHARACTER_FREQ.get(chr(byte).lower(), 0)
    return score

def generate_random_bytes(num_bytes: int) -> bytes:
    return bytes([random.randint(0, 255) for _ in range(num_bytes)])

# Finds byte which was most likely XORed w/ English frequencies
def get_keystream_byte(data):
    best_candidate, score = 0, 0

    # Try all possible bytes
    for key_candidate in range(256):
        curr_score = get_english_score(singlechar_xor(data, key_candidate))
        if curr_score > score:
            score = curr_score
            best_candidate = key_candidate
    return bytes([best_candidate])

# XORs data, from previous set
def xor_data(binary_data_1, binary_data_2):
    return bytes([b1 ^ b2 for b1, b2 in zip(binary_data_1, binary_data_2)])

# XORs single character at a time
def singlechar_xor(input_bytes, key_value):
    output = b''
    for char in input_bytes:
        output += bytes([char ^ key_value])
    return output

# Automated attempt of cracking AES-CTR
def crack_ctr_same_nonce(ciphertexts):
    keystream = b''

    # Take i-th character of each ciphertext to form a column of bytes that were XORed against the same byte
    for i in range(max(map(len, ciphertexts))):
        column = b''
        for c in ciphertexts:
            column += bytes([c[i]]) if i < len(c) else b''

        # Get most likely character that was used for XOR
        keystream += get_keystream_byte(column)

    # Once we got the keystream, we can easily get all the plaintexts
    plaintexts = []
    for c in ciphertexts:
        plaintexts.append(xor_data(c, keystream))
    return plaintexts

if __name__ == '__main__':
    """Crypto Pals Set 3 #18"""
    print(ctr_mode(b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='),
             b'YELLOW SUBMARINE',
             nonce=0))

    """Crypto Pals Set 3 #19"""
    original_plaintexts = []
    ciphertexts = []
    random_key = generate_random_bytes(AES.key_size[0])

    with open("cryptopal19") as f:
        for line in f:
            original_plaintext = b64decode(line)
            original_plaintexts.append(original_plaintext)
            ciphertexts.append(ctr_mode(original_plaintext, random_key, 0))

    cracked_plaintexts = crack_ctr_same_nonce(ciphertexts)

    # Print each cracked plaintext. Some of them will be slightly different from the original plaintext
    # but the attack is not perfect and as long as they are similar I would say that it worked.
    # Prints each plaintext. Some close but not exact.
    for plaintext, original in zip(cracked_plaintexts, original_plaintexts):
        print(plaintext)
