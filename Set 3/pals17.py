from Cryptodome.Cipher import AES
import random
import string

# Set 3 Challenge 17
# Several functions from the previous set(s)
def generate_random_bytes(num_bytes: int) -> bytes:
    return bytes([random.randint(0, 255) for _ in range(num_bytes)])

def fixed_xor(buffer1: bytes, buffer2: bytes) -> bytes:
    return bytes([(b1 ^ b2) for b1, b2 in zip(buffer1, buffer2)])

def bytes_to_str(byte_list: bytes) -> str:
    return "".join(filter(lambda x: x in string.printable, "".join(map(chr, byte_list))))

def aes_in_ecb_mode(byte_string: bytes, key: bytes, encrypt: bool = False) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    if encrypt:
        return cipher.encrypt(byte_string)
    else:
        return cipher.decrypt(byte_string)

def pkcs7_padding(byte_string: bytes, block_length: int) -> bytes:
    num_to_pad = block_length - (len(byte_string) % block_length)
    return byte_string + bytes([num_to_pad]) * num_to_pad

def pkcs7_padding_validation(byte_string: bytes) -> bytes:
    last_byte = byte_string[-1]
    if last_byte > len(byte_string):
        raise ValueError("bad padding")
    for i in range(last_byte, 0, -1):
        if byte_string[-i] != last_byte:
            raise ValueError("bad padding")
    return byte_string[:-last_byte]

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

BLOCK_SIZE = 16
RANDOM_STRINGS = [
        b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']
GLOBAL_KEY = generate_random_bytes(BLOCK_SIZE)

def choose_string():
    return pkcs7_padding(RANDOM_STRINGS[random.randint(0, len(RANDOM_STRINGS)-1)],
                         BLOCK_SIZE)

def cbc_padding_oracle_encrypt(chosen_string=None, print_string=False) -> tuple:
    if chosen_string is None:
        chosen_string = choose_string()
        if print_string:
            print(f"Chosen String: {chosen_string}")
    initialization_vector = generate_random_bytes(BLOCK_SIZE)
    return cbc_mode(chosen_string, GLOBAL_KEY, initialization_vector, encrypt=True), initialization_vector

def cbc_padding_oracle_check(byte_string: bytes, initialization_vector: bytes) -> bool:
    decrypted_string = cbc_mode(byte_string, GLOBAL_KEY, initialization_vector, encrypt=False)
    try:
        pkcs7_padding_validation(decrypted_string)
    except ValueError:
        return False
    else:
        return True

def cbc_one_byte(C_previous, C_current, i, IV, d_C_currents, break_after_first=True):
    P_current_i_possibilities = []
    d_C_current_i_possibilities = []
    for b in range(256):
        C_previous_modified = bytearray(C_previous)
        if len(d_C_currents):
            C_previous_modified[-len(d_C_currents):] = [(BLOCK_SIZE - i) ^ d_C_current_i for d_C_current_i in
                                                        d_C_currents]
        C_previous_modified[i] = b
        if cbc_padding_oracle_check(bytes(C_previous_modified) + C_current, IV):
            d_C_current_i = b ^ (BLOCK_SIZE - i)
            P_current_i = d_C_current_i ^ C_previous[i]
            P_current_i_possibilities.append(P_current_i)
            d_C_current_i_possibilities.append(d_C_current_i)
            if break_after_first:
                break
    return P_current_i_possibilities, d_C_current_i_possibilities

def cbc_one_block(C_previous, C_current, IV):
    plaintext_block = []
    d_C_currents = []
    P_current_16s, d_C_current_16s = cbc_one_byte(C_previous, C_current, 15, IV, [], break_after_first=False)
    for P_current_16, d_C_current_16 in zip(P_current_16s, d_C_current_16s):
        P_current_15s, d_C_current_15s = cbc_one_byte(C_previous, C_current, 14, IV, [d_C_current_16], break_after_first=True)
        if len(P_current_15s):
            plaintext_block = [P_current_15s[0], P_current_16]
            d_C_currents = [d_C_current_15s[0], d_C_current_16]
            break
    for i in range(BLOCK_SIZE-3, -1, -1):
        P_current_is, d_C_current_is = cbc_one_byte(C_previous, C_current, i, IV, d_C_currents, break_after_first=True)
        plaintext_block = [P_current_is[0]] + plaintext_block
        d_C_currents = [d_C_current_is[0]] + d_C_currents
    return plaintext_block

def cbc_padding_oracle_attack(encrypted_string, IV, padding_oracle) -> bytes:
    num_blocks = len(encrypted_string) // BLOCK_SIZE
    plaintext_blocks = []
    C_previous = IV
    for n in range(num_blocks):
        C_current = encrypted_string[n*BLOCK_SIZE: (n+1)*BLOCK_SIZE]
        plaintext_block = cbc_one_block(C_previous, C_current, IV)
        plaintext_blocks.append(bytes(plaintext_block))
        C_previous = C_current
    return b''.join(plaintext_blocks)

if __name__ == '__main__':
    """Crypto Pals Set 3 #17"""
    encrypted_string, iv = cbc_padding_oracle_encrypt()
    print(cbc_padding_oracle_check(encrypted_string, iv))

    CHOSEN_STRING = choose_string()
    encrypted_string, iv = cbc_padding_oracle_encrypt(chosen_string=CHOSEN_STRING)

    C_0 = iv
    C_1 = encrypted_string[:BLOCK_SIZE]
    d_C_1_16s = []
    P_1_16s = []
    for b in range(256):
        C_0_modified = bytearray(C_0)
        C_0_modified[15] = b
        if cbc_padding_oracle_check(bytes(C_0_modified) + C_1, iv):
            d_C_1_16 = b ^ 1
            d_C_1_16s.append(d_C_1_16)
            P_1_16 = d_C_1_16 ^ C_0[15]
            P_1_16s.append(P_1_16)
    print(P_1_16s)
    for P_1_16, d_C_1_16 in zip(P_1_16s, d_C_1_16s):  # this checks both options
        C_0_modified_16 = 2 ^ d_C_1_16
        for b in range(256):
            C_0_modified = bytearray(C_0)
            C_0_modified[15] = C_0_modified_16
            C_0_modified[14] = b
            if cbc_padding_oracle_check(bytes(C_0_modified) + C_1, iv):
                d_C_1_15 = b ^ 2
                P_1_15 = d_C_1_15 ^ C_0[14]
                print(P_1_16, P_1_15)
    d_C_currents = [d_C_1_15, d_C_1_16]
    plaintext_block = [P_1_15, P_1_16]

    C_previous = iv
    C_current = encrypted_string[:BLOCK_SIZE]

    for i in range(BLOCK_SIZE - 3, -1, -1):
        for b in range(256):
            C_previous_modified = bytearray(C_previous)
            if len(d_C_currents):
                C_previous_modified[-len(d_C_currents):] = [(BLOCK_SIZE - i) ^ d_C_current_i for d_C_current_i in
                                                            d_C_currents]
            C_previous_modified[i] = b
            if cbc_padding_oracle_check(bytes(C_previous_modified) + C_current, iv):
                d_C_current_i = b ^ (BLOCK_SIZE - i)
                P_current_i = d_C_current_i ^ C_previous[i]
                plaintext_block = [P_current_i] + plaintext_block
                d_C_currents = [d_C_current_i] + d_C_currents
                break
    print(plaintext_block)
    print([b for b in CHOSEN_STRING[:16]])
    decrypted_string = cbc_padding_oracle_attack(encrypted_string, iv, cbc_padding_oracle_check)
    CHOSEN_STRING == decrypted_string
    print(CHOSEN_STRING)
