from os.path import commonprefix
from pals25 import ctr_mode, GLOBAL_KEY, NONCE

# Set 4 Challenge 26
# CBC Flip mode but edited to CTR mode
def ctr_bitflipping(byte_string: bytes, encrypt=True)->bytes:
    if encrypt:
        prefix = b'comment1=cooking%20MCs;userdata='
        suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
        input_string = (prefix + byte_string + suffix).replace(b';', b'";"').replace(b'=', b'"="')
        return ctr_mode(input_string, GLOBAL_KEY, NONCE)
    else:
        return ctr_mode(byte_string, GLOBAL_KEY, NONCE)

# Checks if CTR bitflipping was successful, returns bool
def ctr_bitflipping_check(byte_string: bytes)->bool:
    decrypted_string = ctr_bitflipping(byte_string, encrypt=False)
    if b';admin=true;' in decrypted_string:
        return True
    else:
        return False

if __name__ == '__main__':
    """CryptoPals Set 4 #26"""
    byte_string = b'xadminxtruex'
    ciphertext = ctr_bitflipping(byte_string)
    len_prefix = len(commonprefix([ctr_bitflipping(b''),
                                   ctr_bitflipping(b'A')]))
    print(len('comment1"="cooking%20MCs";"userdata"="') == len_prefix)

    K_0 = ciphertext[len_prefix + 0] ^ ord('x')
    K_6 = ciphertext[len_prefix + 6] ^ ord('x')
    K_11 = ciphertext[len_prefix + 11] ^ ord('x')
    C_0 = K_0 ^ ord(';')
    C_6 = K_6 ^ ord('=')
    C_11 = K_11 ^ ord(';')
    ciphertext = bytearray(ciphertext)
    ciphertext[len_prefix + 0] = C_0
    ciphertext[len_prefix + 6] = C_6
    ciphertext[len_prefix + 11] = C_11
    ciphertext = bytes(ciphertext)

    print(ctr_bitflipping_check(ciphertext))