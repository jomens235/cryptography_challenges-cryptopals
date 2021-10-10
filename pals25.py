from binascii import a2b_base64
from itertools import islice
import string
from Cryptodome.Cipher import AES
import random

# Set 4 Challenge 25
# Functions previously used in other sets:
def generate_random_bytes(num_bytes: int) -> bytes:
    return bytes([random.randint(0, 255) for _ in range(num_bytes)])

def fixed_xor(buffer1: bytes, buffer2: bytes) -> bytes:
    return bytes([(b1 ^ b2) for b1, b2 in zip(buffer1, buffer2)])

def aes_in_ecb_mode(byte_string: bytes, key: bytes, encrypt: bool = False) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    if encrypt:
        return cipher.encrypt(byte_string)
    else:
        return cipher.decrypt(byte_string)

def pkcs7_padding(byte_string: bytes, block_length: int) -> bytes:
    num_to_pad = block_length - (len(byte_string) % block_length)
    return byte_string + bytes([num_to_pad]) * num_to_pad

def cbc_mode(byte_string: bytes,
             key: bytes,
             initialization_vector: bytes,
             encrypt: bool = True) -> bytes:
    if encrypt:
        previous_block = initialization_vector
        cipher_text = b''
        for i in range(0, len(byte_string), len(key)):
            plain_text = fixed_xor(pkcs7_padding(byte_string[i: i + len(key)], len(key)),
                                   previous_block)
            previous_block = aes_in_ecb_mode(plain_text, key, encrypt=True)
            cipher_text += previous_block
        return cipher_text
    else:
        previous_block = initialization_vector
        plain_text = b''
        for i in range(0, len(byte_string), len(key)):
            cipher_text = byte_string[i: i + len(key)]
            plain_text += fixed_xor(aes_in_ecb_mode(cipher_text, key, encrypt=False), previous_block)
            previous_block = cipher_text
        return plain_text

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

def bytes_to_str(byte_list: bytes) -> str:
    return "".join(filter(lambda x: x in string.printable, "".join(map(chr, byte_list))))

BLOCK_SIZE = 16
GLOBAL_KEY = generate_random_bytes(BLOCK_SIZE)
NONCE = 42

# Function to 'seek' into ciphertext
def ctr_edit(ciphertext, offset, newtext):
    keystream = islice(ctr_keystream(GLOBAL_KEY, NONCE), offset, offset + len(newtext))
    return ciphertext[:offset] + fixed_xor(newtext, keystream) + ciphertext[offset + len(newtext):]


if __name__ == '__main__':
    """CryptoPals Set 4 #25"""
    byte_string = b''.join([a2b_base64(line.strip()) for line in open("cryptopal25").readlines()])
    plaintext = aes_in_ecb_mode(byte_string, b'YELLOW SUBMARINE', encrypt=False)
    for line in bytes_to_str(plaintext).split("\n")[:10]:
        print(line)

    ciphertext = ctr_mode(plaintext, GLOBAL_KEY, nonce=NONCE)
    example = ctr_edit(ciphertext, 10, b"new encrypt key")
    print([x for x in example[:20]])
    print([x for x in ciphertext[:20]])

    real_keystream = bytes(list(islice(ctr_keystream(GLOBAL_KEY, NONCE), 0, len(ciphertext))))
    predicted_keystream = ctr_edit(ciphertext, 0, bytes([0] * len(ciphertext)))
    print(real_keystream == predicted_keystream)

    predicted_plaintext = fixed_xor(ciphertext, predicted_keystream)
    for line in bytes_to_str(predicted_plaintext).split("\n")[:10]:
        print(line)