import struct
from binascii import hexlify
from pals25 import generate_random_bytes
from pals28 import left_rotate

# Set 4 Challenge 30:
MASK = 0xffffffff
BLOCK_SIZE = 16
GLOBAL_KEY = generate_random_bytes(BLOCK_SIZE)

# Breaks a msg into chunks
def chunks(message, chunk_size=64):
    for i in range(0, len(message), chunk_size):
        yield message[i: i+chunk_size]

# Functions created from pseudo code from practicalcryptography.com
def md4(message: bytes, h0=0x67452301, h1=0xefcdab89, h2=0x98badcfe, h3=0x10325476):
    message = message + get_md4_padding(len(message))
    return md4_no_padding(message, h0, h1, h2, h3)

# Pads MD4 input
def get_md4_padding(m1: int) -> bytes:
    padding = b'\x80'
    padding += b'\x00' * ((56 - (m1 + 1) % 64) % 64)
    padding += struct.pack(b'<Q', m1 * 8) # THIS LINE IS DIFFERENT FROM SHA-1
    return padding

# MD4 without padding
def md4_no_padding(message: bytes, h0=0x67452301, h1=0xefcdab89, h2=0x98badcfe, h3=0x10325476):
    _F = lambda x, y, z: ((x & y) | (~x & z))
    _G = lambda x, y, z: ((x & y) | (x & z) | (y & z))
    _H = lambda x, y, z: (x ^ y ^ z)
    round_1 = lambda w, x, y, z, k, s: left_rotate((w + _F(x, y, z) + X[k]) & MASK, s)
    round_2 = lambda w, x, y, z, k, s: left_rotate((w + _G(x, y, z) + X[k] + 0x5a827999) & MASK, s)
    round_3 = lambda w, x, y, z, k, s: left_rotate((w + _H(x, y, z) + X[k] + 0x6ed9eba1) & MASK, s)

    for chunk in chunks(message):
        X = list(struct.unpack('<' + 'I' * 16, chunk))
        a, b, c, d = h0, h1, h2, h3

        # Round 1
        a = round_1(a, b, c, d, 0, 3)
        d = round_1(d, a, b, c, 1, 7)
        c = round_1(c, d, a, b, 2, 11)
        b = round_1(b, c, d, a, 3, 19)

        a = round_1(a, b, c, d, 4, 3)
        d = round_1(d, a, b, c, 5, 7)
        c = round_1(c, d, a, b, 6, 11)
        b = round_1(b, c, d, a, 7, 19)

        a = round_1(a, b, c, d, 8, 3)
        d = round_1(d, a, b, c, 9, 7)
        c = round_1(c, d, a, b, 10, 11)
        b = round_1(b, c, d, a, 11, 19)

        a = round_1(a, b, c, d, 12, 3)
        d = round_1(d, a, b, c, 13, 7)
        c = round_1(c, d, a, b, 14, 11)
        b = round_1(b, c, d, a, 15, 19)

        # Round 2
        a = round_2(a, b, c, d, 0, 3)
        d = round_2(d, a, b, c, 4, 5)
        c = round_2(c, d, a, b, 8, 9)
        b = round_2(b, c, d, a, 12, 13)

        a = round_2(a, b, c, d, 1, 3)
        d = round_2(d, a, b, c, 5, 5)
        c = round_2(c, d, a, b, 9, 9)
        b = round_2(b, c, d, a, 13, 13)

        a = round_2(a, b, c, d, 2, 3)
        d = round_2(d, a, b, c, 6, 5)
        c = round_2(c, d, a, b, 10, 9)
        b = round_2(b, c, d, a, 14, 13)

        a = round_2(a, b, c, d, 3, 3)
        d = round_2(d, a, b, c, 7, 5)
        c = round_2(c, d, a, b, 11, 9)
        b = round_2(b, c, d, a, 15, 13)

        # Round 3
        a = round_3(a, b, c, d, 0, 3)
        d = round_3(d, a, b, c, 8, 9)
        c = round_3(c, d, a, b, 4, 11)
        b = round_3(b, c, d, a, 12, 15)

        a = round_3(a, b, c, d, 2, 3)
        d = round_3(d, a, b, c, 10, 9)
        c = round_3(c, d, a, b, 6, 11)
        b = round_3(b, c, d, a, 14, 15)

        a = round_3(a, b, c, d, 1, 3)
        d = round_3(d, a, b, c, 9, 9)
        c = round_3(c, d, a, b, 5, 11)
        b = round_3(b, c, d, a, 13, 15)

        a = round_3(a, b, c, d, 3, 3)
        d = round_3(d, a, b, c, 11, 9)
        c = round_3(c, d, a, b, 7, 11)
        b = round_3(b, c, d, a, 15, 15)

        h0 = (h0 + a) & MASK
        h1 = (h1 + b) & MASK
        h2 = (h2 + c) & MASK
        h3 = (h3 + d) & MASK
    return struct.pack('<IIII', h0, h1, h2, h3)

def MAC_md4(message: bytes, key=GLOBAL_KEY, h0=0x67452301, h1=0xefcdab89, h2=0x98badcfe, h3=0x10325476) -> bytes:
    return md4(key + message, h0, h1, h2, h3)

# Main function
if __name__ == '__main__':
    """CryptoPals Set 4 #30"""
    print(hexlify(md4(b"The quick brown fox jumps over the lazy dog")) == b"1bee69a46ba811185c194762abaeae90")
    print(hexlify(md4(b"The quick brown fox jumps over the lazy cog")) == b"b86e130ce7028da59e672d56ad0113df")

    original_message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    mac = MAC_md4(original_message)

    new_message = b";admin=true;"

    h0 = int.from_bytes(mac[0:4], byteorder='little')
    h1 = int.from_bytes(mac[4:8], byteorder='little')
    h2 = int.from_bytes(mac[8:12], byteorder='little')
    h3 = int.from_bytes(mac[12:16], byteorder='little')

    for key_length in range(64):
        glue_padding = get_md4_padding(key_length + len(original_message))
        new_padding = get_md4_padding(len(new_message) + \
                                      key_length + len(original_message) + len(glue_padding))
        new_mac = md4_no_padding(new_message + new_padding, h0, h1, h2, h3)
        if new_mac == MAC_md4(original_message + glue_padding + new_message):
            print(f"Success! Key length {key_length}")
