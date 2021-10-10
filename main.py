import base64
from base64 import b64encode, b64decode
from binascii import unhexlify, hexlify, a2b_base64
import string
from Cryptodome.Cipher import AES

# Set 1 #1:
# Converts hex code to base 64
def hextobase64(str):
    str = b64encode(bytes.fromhex(str)).decode()
    return str

# Set 1 #2:
# Fixed XOR function between two bytes
def fixedxor(byte1, byte2):
    b = bytearray(len(byte1))
    for i in range(len(byte1)):
        b[i] = byte1[i] ^ byte2[i]
    return (b)

# Set 1 #3:
# Converts bytes input to string for printing
def bytes_to_str(byte_list: bytes) -> str:
    return "".join(filter(lambda x: x in string.printable, "".join(map(chr, byte_list))))

# XORs a single byte, uses character frequency to determine decryption
def single_byte_xor_cipher(byte_string: bytes) -> tuple:
    english_character_frequency = {'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75, 'S': 6.33,
                                   'H': 6.09,
                                   'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
                                   'F': 2.23,
                                   'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29, 'V': 0.98, 'K': 0.77, 'J': 0.15,
                                   'X': 0.15,
                                   'Q': 0.10, 'Z': 0.07, ' ': 35}
    strings = [fixedxor(byte_string, bytearray(bytes([num]) * len(byte_string))) for num in range(256)]
    scores = [
        sum([bytes_to_str(s).upper().count(c) * english_character_frequency[c] for c in english_character_frequency])
        for s in strings]
    index = max(range(len(scores)), key=scores.__getitem__)
    return strings[index], max(scores), index

# Set 1 #4:
# Searches through file specified to find 'Now that the party is jumping'
def detect_single_byte_xor_cipher(byte_strings: list) -> bytes:
    scored_strings = []
    for line in byte_strings:
        try:
            line.decode('ascii')
            scored_strings.append(single_byte_xor_cipher(line))
        except UnicodeDecodeError:
            pass
    return sorted(scored_strings, key=lambda x: x[1], reverse=True)[0][0]

# Set 1 #5:
# Encrypts string with fixed XOR using a key. Very similar to Vigenere Cipher
def repeating_key_xor(byte_string: bytes, byte_key: bytes) -> bytes:
    return fixedxor(byte_string, (byte_key * len(byte_string))[:len(byte_string)])

# Set 1 #6:
# Calculates distance between repeating bits in the inputs
# Used with other functions in Set 1 to find the answer
def hamm_dist(buffer1: bytes, buffer2: bytes) -> int:
    distance = sum(bin(i).count("1") for i in fixedxor(buffer1, buffer2))
    return distance

# Set 1 #7:
# Implements AES ECB mode using PyCryptodomex package
def aes_ecb_mode(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# Set 1 #8:
# Detects AES ECB in a file and locates the string encrypted using AES
def detect_aes_ecb_mode(byte_string: bytes,
                        block_length: int) -> bool:
    byte_blocks = [byte_string[i * block_length: (i + 1) * block_length]
                   for i in range(int(len(byte_string) / block_length))]
    unique_blocks = set(byte_blocks)
    return len(unique_blocks) / len(byte_blocks) < 1

if __name__ == '__main__':
    """Crypto Pals Set 1 #1"""
    # word = input("Enter a hex string: ")
    # b64 = hextobase64(word)
    # print(b64)

    """Crypto Pals Set 1 #2"""
    # byte1 = bytearray.fromhex("1c0111001f010100061a024b53535009181c")
    # byte2 = bytearray.fromhex("686974207468652062756c6c277320657965")
    # b = bytes(fixedxor(byte1, byte2))
    # print(b)

    """Crypto Pals Set 1 #3"""
    # print(bytes_to_str(single_byte_xor_cipher(unhexlify("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))[0]))

    """Crypto Pals Set 1 #4"""
    # byte_strings = [unhexlify(line.strip()) for line in open("cryptopal4").readlines()]
    # print(bytes_to_str(detect_single_byte_xor_cipher(byte_strings).strip()))

    """Crypto Pals Set 1 #5"""
    # pt = b"Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
    # key = b"ICE"
    # hexlify(pt)
    # hexlify(key)
    # print(hexlify(repeating_key_xor(pt, key)))

    """Crypto Pals Set 1 #6"""
    # byte_string = b''.join([a2b_base64(line.strip()) for line in open("cryptopal6").readlines()])
    # keysize_distances = []
    # for keysize in range(2, 40):
    #    blocks = [byte_string[i * keysize: (i + 1) * keysize] for i in range(4)]
    #    distances = [hamm_dist(blocks[i], blocks[j]) for i in range(len(blocks) - 1) for j in
    #                 range(1, len(blocks))]
    #    distance = sum(distances) / len(distances)
    #    distance /= keysize
    #    keysize_distances.append((keysize, distance))
    # keysize = sorted(keysize_distances, key=lambda x: x[1])[0][0]

    # byte_blocks = [byte_string[i * keysize: (i + 1) * keysize] for i in range(int(len(byte_string) / keysize))]
    # transposed_blocks = [bytearray([b[i] for b in byte_blocks]) for i in range(keysize)]
    # keys = []
    # for block in transposed_blocks:
    #    _, _, index = single_byte_xor_cipher(block)
    #    keys.append(index)
    # key = bytearray(keys)
    # print(bytes_to_str(key))

    """Crypto Pals Set 1 #7"""
    # key = b'YELLOW SUBMARINE'
    # with open('cryptopal7') as fh:
    #    ciphertext = base64.b64decode(fh.read())
    # msg = aes_ecb_mode(ciphertext, key)
    # print(msg)

    """Crypto Pals Set 1 #8"""
    # byte_strings = [unhexlify(line.strip()) for line in open("cryptopal8").readlines()]
    # BLOCK_SIZE = 16
    # print([i for i, byte_string in enumerate(byte_strings) if detect_aes_ecb_mode(byte_string, BLOCK_SIZE)])
