import struct
import hashlib

# Set 4 Challenge 28
# Rotates bits left by input shift
def left_rotate(value, shift):
    return ((value << shift) & 0xffffffff) | (value >> (32 - shift))

# Pure SHA-1 implementation in python based off of pseudo-code, extra parameters for implementation in 29
def sha1(message, ml=None, h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0):
    # Pre-processing:
    if ml is None:
        ml = len(message) * 8

    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'

    message += struct.pack('>Q', ml)

    # Process message in 512-bit chunks:
    for i in range(0, len(message), 64):

        # Break chunk into 16, 32-bit big-endian ints w[i]
        w = [0] * 80
        for j in range(16):
            w[j] = struct.unpack('>I', message[i + j * 4:i + j * 4 + 4])[0]

        # Extend the 16, 32-bit ints into 80, 32-bit ints
        for j in range(16, 80):
            w[j] = left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)

        # Init hash vals for chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # Main loop
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

        # Add this chunk's hash to current result:
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    # Produce final hash value (big-endian) as a 160 bit number, hex formatted
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)


# Main function
if __name__ == '__main__':
    """Crypto Pals Set 4 #28"""
    key = b'RandOm texT As kEY'
    message = b'Test message to make sure I get the same result.'
    hashed = sha1(key + message)

    # Verify correct implementation
    h = hashlib.sha1(key + message)
    print(h.hexdigest() == hashed)
