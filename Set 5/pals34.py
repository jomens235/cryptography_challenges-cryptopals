import struct
from Cryptodome import Random
from Cryptodome.Cipher import AES
from pals33 import DiffieHellman
from binascii import unhexlify


# Set 5 Challenge 34
# All functions below are taken from previous sets:
def aes_ecb_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(data, AES.block_size))

def pkcs7_pad(message, block_size):
    if len(message) == block_size:
        return message
    ch = block_size - len(message) % block_size
    return message + bytes([ch] * ch)

def aes_cbc_encrypt(data, key, iv):
    ciphertext = b''
    prev = iv
    for i in range(0, len(data), AES.block_size):
        curr_plaintext_block = pkcs7_pad(data[i:i + AES.block_size], AES.block_size)
        block_cipher_input = xor_data(curr_plaintext_block, prev)
        encrypted_block = aes_ecb_encrypt(block_cipher_input, key)
        ciphertext += encrypted_block
        prev = encrypted_block

    return ciphertext

def aes_ecb_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return pkcs7_unpad(cipher.decrypt(data))

def pkcs7_unpad(data):
    if len(data) == 0:
        raise Exception("The input data must contain at least one byte")
    if not is_pkcs7_padded(data):
        return data

    padding_len = data[len(data) - 1]
    return data[:-padding_len]

def is_pkcs7_padded(binary_data):
    padding = binary_data[-binary_data[-1]:]

    return all(padding[b] == len(padding) for b in range(0, len(padding)))

def aes_cbc_decrypt(data, key, iv, unpad=True):
    plaintext = b''
    prev = iv

    for i in range(0, len(data), AES.block_size):
        curr_ciphertext_block = data[i:i + AES.block_size]
        decrypted_block = aes_ecb_decrypt(curr_ciphertext_block, key)
        plaintext += xor_data(prev, decrypted_block)
        prev = curr_ciphertext_block

    return pkcs7_unpad(plaintext) if unpad else plaintext

def xor_data(binary_data_1, binary_data_2):
    return bytes([b1 ^ b2 for b1, b2 in zip(binary_data_1, binary_data_2)])

def left_rotate(value, shift):
    return ((value << shift) & 0xffffffff) | (value >> (32 - shift))

def sha1(message, ml=None, h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0):
    if ml is None:
        ml = len(message) * 8

    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'

    message += struct.pack('>Q', ml)

    for i in range(0, len(message), 64):

        w = [0] * 80
        for j in range(16):
            w[j] = struct.unpack('>I', message[i + j * 4:i + j * 4 + 4])[0]
        for j in range(16, 80):
            w[j] = left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        for j in range(80):
            if j <= 19:
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (d & (b | c))
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = left_rotate(a, 5) + f + e + k + w[j] & 0xffffffff
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

# Here starts the actual program for challenge 34
# Network part is simulated for convenience
# This simulates MITM key-fixing on diffie hellman by param injection
def parameter_injection_attack(alice, bob):
    # Step 1: Alice computes A and sends it to the MITM (thinking of Bob)
    A = alice.get_public_key()

    # Step 2: the MITM changes A with p and sends it to Bob
    A = alice.p

    # Step 3: Bob computes B and sends it to the MITM (thinking of Alice)
    B = bob.get_public_key()

    # Step 4: the MITM changes B with p and sends it to Alice
    B = bob.p

    # Step 5: Alice finally sends her encrypted message to Bob (without knowledge of MITM)
    _msg = b'Hello, how are you?'
    _a_key = unhexlify(sha1(str(alice.get_shared_secret_key(B)).encode()))[:16]
    _a_iv = Random.new().read(AES.block_size)
    a_question = aes_cbc_encrypt(_msg, _a_key, _a_iv) + _a_iv

    # Step 6: the MITM relays that to Bob
    # Doesn't actually need to do anything since I already have access to it

    # Step 7: Bob decrypts the message sent by Alice (without knowing of the attack), encrypts it and sends it again
    _b_key = unhexlify(sha1(str(bob.get_shared_secret_key(A)).encode()))[:16]
    _a_iv = a_question[-AES.block_size:]
    _a_message = aes_cbc_decrypt(a_question[:-AES.block_size], _b_key, _a_iv)
    _b_iv = Random.new().read(AES.block_size)
    b_answer = aes_cbc_encrypt(_a_message, _b_key, _b_iv) + _b_iv

    # Step 8: the MITM relays that to Alice
    # Again, already have access I don't need to send it

    # Step 9: the MITM decrypts the message (either from a_question or from b_answer, it's the same).
    #
    # Finding the key after replacing A and B with p is, in fact, very easy.
    # Instead of (B^a % p) or (A^b % p), the shared secret key of the exercise became (p^a % p)
    # and (p^b % p), both equal to zero!
    mitm_hacked_key = unhexlify(sha1(b'0').encode())[:16]

    # Hack Alice's question
    mitm_a_iv = a_question[-AES.block_size:]
    mitm_hacked_message_a = aes_cbc_decrypt(a_question[:-AES.block_size], mitm_hacked_key, mitm_a_iv)

    # Hack Bob's answer (which here is the same)
    mitm_b_iv = b_answer[-AES.block_size:]
    mitm_hacked_message_b = aes_cbc_decrypt(b_answer[:-AES.block_size], mitm_hacked_key, mitm_b_iv)

    # If assert fails then it won't print, but it will throw an error.
    assert _msg == mitm_hacked_message_a == mitm_hacked_message_b
    print("The attack finished successfully.")


# Main function
if __name__ == '__main__':
    """CryptoPals Set 5 #34"""
    alice = DiffieHellman()
    bob = DiffieHellman()
    parameter_injection_attack(alice, bob)
