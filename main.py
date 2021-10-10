import re
from binascii import hexlify, unhexlify, a2b_base64
import string
import base64
from collections import OrderedDict
from os.path import commonprefix
from Cryptodome.Cipher import AES
import random

# Set 2 Challenge 9:
# Adds padding to a byte by adding "\x04"
# Ends up printing out zeroes on the end of the string.
def pkcs7pad(string_in, length):
    while len(string_in) < length:
        string_in = string_in + "\x04"
    return string_in

# Set 2 Challenge 10:
# First 3 functions are from Set 1:
def fixedxor(byte1, byte2):
    b = bytearray(len(byte1))
    for i in range(len(byte1)):
        b[i] = byte1[i] ^ byte2[i]
    return (b)

def bytes_to_str(byte_list: bytes) -> str:
    return "".join(filter(lambda x: x in string.printable, "".join(map(chr, byte_list))))

def aes_ecb_mode(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# CBC mode for decrypting the message from the file
# Prints out the decrypted message, starts with "I'm back and I'm ringin' the bell..."
def cbc_mode(byte_string: bytes, key: bytes, initialization_vector: bytes, encrypt: bool = True) -> bytes:
    if encrypt:
        previous_block = initialization_vector
        cipher_text = b''
        for i in range(int(len(byte_string) / len(key))):
            plain_text = fixedxor(byte_string[i * len(key): (i + 1) * len(key)], previous_block)
            previous_block = aes_ecb_mode(plain_text, key)
            cipher_text += previous_block
        return cipher_text
    else:
        previous_block = initialization_vector
        plain_text = b''
        for i in range(int(len(byte_string) / len(key))):
            cipher_text = byte_string[i * len(key): (i + 1) * len(key)]
            plain_text += fixedxor(aes_ecb_mode(cipher_text, key), previous_block)
            previous_block = cipher_text
        return plain_text

# Set 2 Challenge 11:
# Generates random bytes for the input int
def generate_random_bytes(num_bytes: int) -> bytes:
    return bytes([random.randint(0, 255) for _ in range(num_bytes)])

# Makes a random string for the length bytes in length
# Takes in int, returns str
def random_key(length):
    key = b''
    choices = list(range(256))
    for i in range(length):
        choice = random.choice(choices)
        hexVal = hex(choice).lstrip('0x')
        if len(hexVal) % 2 != 0:
            hexVal = '0' + hexVal
        key += bytes.fromhex(hexVal)

    if len(key) % length != 0:
        key += bytes(length - len(key) % length)
    return key

# Pads the input message with 5-10 rand bytes on both ends, then PKCS#7 pad
#In: bytes, Out: bytes
def pad(msg):
    leftPadCnt = random.randint(5, 10)
    rightPadCnt = random.randint(5, 10)
    leftPad = random_key(leftPadCnt)
    rightPad = random_key(rightPadCnt)
    paddedMsg = leftPad + msg + rightPad
    size = 16
    length = len(paddedMsg)
    if length % size == 0:
        return paddedMsg

    # PKCS 7 pad if pt after padding isn't multiple of block size
    padding = size - (length % size)
    padValue = hex(padding).lstrip('0x')
    if len(padValue) == 1:
        padValue = '0' + padValue  # Bytes can't convert single digit hex
    padValue = bytes.fromhex(padValue)
    paddedMsg += padValue * padding
    return paddedMsg

# Encrypts message with AES CBC or ECB mode
# In: Bytes, Out: Bytes
def encryption_oracle(msg):
    mode = random.randint(0, 1)
    key = random_key(16)
    print(f"Key: { key }")
    paddedMsg = pad(msg)

    if mode:
        print("Chose ECB Mode")
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(paddedMsg)
    else:
        print("Chose CBC Mode")
        iv = random_key(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(paddedMsg)
    return ciphertext

# Finds of ciphertext was created with ECB or CBC mode
# In: Bytes, Out: Str
def detect(cipher):
    chunkSize = 16
    chunks = []
    for i in range(0, len(cipher), chunkSize):
        chunks.append(cipher[i:i+chunkSize])

    uniqueChunks = set(chunks)
    if len(chunks) > len(uniqueChunks):
        return "ECB"
    return "CBC"

# Function from previous set
def detect_aes_ecb_mode(byte_string: bytes,
                        block_length: int) -> bool:
    byte_blocks = [byte_string[i * block_length: (i + 1) * block_length]
                   for i in range(int(len(byte_string) / block_length))]
    unique_blocks = set(byte_blocks)
    return len(unique_blocks) / len(byte_blocks) < 1

# Set 2 Challenge 12:
UNKNOWN_STRING = b"""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""
KEY = random_key(16)

# Second padding func, In: bytes and bytes, Out: bytes
def pad2(your_string, msg):
    paddedMsg = your_string + msg
    size = 16
    length = len(paddedMsg)
    if length % size == 0:
        return paddedMsg
    # PKCS 7 pad if pt after padding isn't multiple of block size
    padding = size - (length % size)
    padValue = bytes([padding])
    paddedMsg += padValue * padding
    return paddedMsg

# Encryption oracle similar to prob 11's
def encryption_oracle(your_string):
    msg = bytes('Decrypted string:\n', 'ascii')
    plaintext = msg + base64.b64decode(UNKNOWN_STRING)
    paddedPlaintext = pad2(your_string, plaintext)
    cipher = AES.new(KEY, AES.MODE_ECB)
    ciphertext = cipher.encrypt(paddedPlaintext)
    return ciphertext

# Finds block size used by the encryption oracles
def detect_block_size():
    feed = b"A"
    length = 0
    while True:
        cipher = encryption_oracle(feed)
        # add 1 character per iteration
        feed += feed
        if not length == 0 and len(cipher) - length > 1:
            return len(cipher) - length
        length = len(cipher)

# Finds which mode was used during encryption
def detect_mode(cipher):
    chunkSize = 16
    chunks = []
    for i in range(0, len(cipher), chunkSize):
        chunks.append(cipher[i:i + chunkSize])

    uniqueChunks = set(chunks)
    if len(chunks) > len(uniqueChunks):
        return "ECB"
    return "not ECB"

# Decrypts ECB mode without a key w/ Byte at a time attack
def ecb_decrypt(block_size):
    # common = lower_cases + upper_cases + space + numbers
    common = list(range(ord('a'), ord('z'))) + list(range(ord('A'), ord('Z'))) + [ord(' ')] + list(
        range(ord('0'), ord('9')))
    rare = [i for i in range(256) if i not in common]
    possibilities = bytes(common + rare)

    plaintext = b''  # holds the plaintext
    check_length = block_size

    while True:
        prepend = b'A' * (block_size - 1 - (len(plaintext) % block_size))
        actual = encryption_oracle(prepend)[:check_length]
        found = False
        for byte in possibilities:
            value = bytes([byte])
            your_string = prepend + plaintext + value
            produced = encryption_oracle(your_string)[:check_length]
            if actual == produced:
                plaintext += value
                found = True
                break
        if not found:
            print(f'Possible end of plaintext: No matches found.')
            print(f"Plaintext: \n{plaintext.decode('ascii')}")
            return
        if len(plaintext) % block_size == 0:
            check_length += block_size

# Set 2 Challenge 13:
USER_DB = OrderedDict()
user_cnt = 0
KEY = random_key(16)

# Class creates JSON-like objects from cookies
class objectify:
    def __init__(self, cookie):
        self.cookie = cookie
        self.obj = OrderedDict()

    # Converts cookie objects into dictionary
    def convert(self):
        # Already converted
        if len(self.obj) > 0:
            return self.obj

        kv = self.cookie.split('&')
        for pair in kv:
            k, v = pair.split('=')
            self.obj[k] = v
        return self.obj

    # Converts dictionary to JSON format
    def __repr__(self):
        self.convert()
        ret_value = "{\n"
        last_key = next(reversed(self.obj))
        for key, value in self.obj.items():
            if not key == last_key:
                ret_value += f"\t{key}: '{value}',\n"
            else:
                ret_value += f"\t{key}: '{value}'\n"
        ret_value += "}"
        return ret_value

# Third version of the padding function since the other 2 have problems with certain functions
def pad3(value, size):
    if len(value) % size == 0:
        return value
    padding = size - len(value) % size
    padValue = bytes([padding]) * padding
    return value + padValue

# Generates encrypted profile info
def profile_for(user_info):
    # get cookie from user_info
    global user_cnt
    user_info = re.sub("&|=", "", user_info)
    cookie = f"email={user_info}&uid={user_cnt}&role=user"
    user_cnt += 1

    # Encrypt cookie info
    paddedCookie = pad3(bytes(cookie, 'ascii'), AES.block_size)
    ecb = AES.new(KEY, AES.MODE_ECB)
    cipherCookie = ecb.encrypt(paddedCookie)

    return cipherCookie

# Decrypts the encoded profiles
def decrypt_profile(key, cipherCookie):
    ecb = AES.new(key, AES.MODE_ECB)
    plainCookie = ecb.decrypt(cipherCookie)

    # Remove padding
    last_byte = plainCookie[-1]
    # padding is a number that's value ranges from 0 to block_size - 1
    if last_byte in range(AES.block_size - 1):
        padding = bytes([last_byte]) * last_byte
        # check if last byte is padding byte
        if plainCookie[-last_byte:] == padding:
            plainCookie = plainCookie[:-plainCookie[-1]]

    # Convert cookie -> object format
    cookie = plainCookie.decode('ascii')
    obj = objectify(cookie)
    return cookie, str(obj)

# Creates the 'admin profile' with the key
def create_admin_profile():
    cookie_parts = 'email=@gmail.com&uid=2&role='
    username = 'A' * (AES.block_size - len(cookie_parts) % AES.block_size)
    email = username + "@gmail.com"
    cipherCookie1 = profile_for(email)

    # Email and admin take up a full block
    cookie_param = "email="
    hacker_mail = 'A' * (AES.block_size - len(cookie_param) % AES.block_size)
    value = pad3(b'admin', AES.block_size).decode('ascii')
    hacker_mail += value
    cipherCookie2 = profile_for(hacker_mail)

    block1 = cipherCookie1[:-AES.block_size]
    block2 = cipherCookie2[AES.block_size:AES.block_size * 2]
    cipherBlock = block1 + block2

    cookie, obj = decrypt_profile(KEY, cipherBlock)
    print(f"Cookie Created: {cookie}")
    print(f"Object Created: {obj}")

# Set 2 Challenge 14:
UNKNOWN_STRING = b"""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

KEY = random_key(16)
prefix_length = random.randint(1, 3 * AES.block_size)
PREFIX = random_key(prefix_length)

# Finds the block size used by the encryption oracle
def detect_block_size():
    feed = b"A"
    length = 0
    while True:
        cipher = encryption_oracle(feed)
        # Add a char each iteration
        feed += feed
        if not length == 0 and len(cipher) - length > 1:
            return len(cipher) - length
        length = len(cipher)

# Finds the mode that was used in encryption
def detect_mode(cipher):
    chunkSize = 16
    chunks = []
    for i in range(0, len(cipher), chunkSize):
        chunks.append(cipher[i:i + chunkSize])

    uniqueChunks = set(chunks)
    if len(chunks) > len(uniqueChunks):
        return "ECB"
    return "not ECB"

# Finds the length of the prefix used in oracle
def detect_prefix_length():
    block_size = detect_block_size()

    # Find number of int blocks occupied
    test_case_1 = encryption_oracle(b'a')
    test_case_2 = encryption_oracle(b'b')

    length1 = len(test_case_1)
    length2 = len(test_case_2)

    blocks = 0
    min_length = min(length1, length2)
    # If the any of the blocks (starting from the left) are the same, they are 'PREFIX'
    for i in range(0, min_length, block_size):
        if test_case_1[i:i + block_size] != test_case_2[i:i + block_size]:
            break
        blocks += 1

    test_input = b''
    length = blocks * block_size
    for extra in range(block_size):
        test_input += b'?'
        curr = encryption_oracle(test_input)[length: length + block_size]
        next = encryption_oracle(test_input + b'?')[length: length + block_size]
        if curr == next:
            break

    residue = block_size - len(test_input)
    length += residue
    return length

# Decrypts plaintext without a key w/ Byte at a Time attack
def ecb_decrypt(block_size):
    # common = lower_cases + upper_cases + space + numbers
    common = list(range(ord('a'), ord('z'))) + list(range(ord('A'), ord('Z'))) + [ord(' ')] + list(
        range(ord('0'), ord('9')))
    rare = [i for i in range(256) if i not in common]
    possibilities = bytes(common + rare)

    plaintext = b''
    check_length = block_size

    prefix_len = detect_prefix_length()
    print(f"Calculated Length of Prefix = {prefix_len}")
    check_begin = (prefix_len // block_size) * block_size
    residue = prefix_len % block_size

    while True:
        prepend = b'A' * (block_size - 1 - (len(plaintext) + residue) % block_size)
        actual = encryption_oracle(prepend)[check_begin: check_begin + check_length]

        found = False
        for byte in possibilities:
            value = bytes([byte])
            your_string = prepend + plaintext + value
            produced = encryption_oracle(your_string)[check_begin: check_begin + check_length]
            if actual == produced:
                plaintext += value
                found = True
                break

        if not found:
            print(f'Possible end of plaintext: No matches found.')
            print(f"Plaintext: \n{plaintext.decode('ascii')}")
            return

        if (len(plaintext) + residue) % block_size == 0:
            check_length += block_size

# Set 2 Challenge 15:
# Checks if padding is added properly
def pkcs7_padding_validation(byte_string: bytes)->bytes:
    last_byte = byte_string[-1]
    if last_byte > len(byte_string):
        return ValueError("bad padding")
    for i in range(last_byte, 0, -1):
        if byte_string[-i] != last_byte:
            raise ValueError("bad padding")
    return byte_string[:-last_byte]

# Set 2 Challenge 16:
RANDOM_INITIALIZATION_VECTOR = generate_random_bytes(16)
GLOBAL_KEY = random_key(16)

def cbc_bitflipping(byte_string: bytes, encrypt=True)->bytes:
    if encrypt:
        prefix = b'comment1=cooking%20MCs;userdata='
        suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
        input_string = (prefix + byte_string + suffix).replace(b';', b'";"').replace(b'=', b'"="')
        return cbc_mode(pkcs7pad(input_string, 16), GLOBAL_KEY, RANDOM_INITIALIZATION_VECTOR, encrypt=True)
    else:
        return cbc_mode(byte_string, GLOBAL_KEY, RANDOM_INITIALIZATION_VECTOR, encrypt=False)

def cbc_bitflipping_check(byte_string:bytes)->bool:
    decrypted_string = cbc_bitflipping(byte_string, encrypt=False)
    if b';admin=true;' in decrypted_string:
        return True
    else:
        return False

def cbc_bitflipping_attack(encryptor, checker):
    # Number of blocks taken up by prefix:
    num_prefix_blocks = len(commonprefix([encryptor(b''),
                                          encryptor(b'A')])) // 16 + 1

    # Number of extra letters to add so
    # prefix + extra takes up a whole number of blocks
    encrypted_strings = [encryptor(b'A' * 0)]
    min_addition = None
    for i in range(1, 16):
        encrypted_strings.append(encryptor(b'A' * i))
        length_common_prefix = len(commonprefix(encrypted_strings))
        if length_common_prefix == num_prefix_blocks * 16:
            min_addition = i - 1
            break
        encrypted_strings = [encrypted_strings[-1]]
    assert min_addition is not None

    encrypted = encryptor(b'A' * min_addition + b'xadminxtruex')
    previous_block = [p for p in encrypted[(num_prefix_blocks - 1) * 16: num_prefix_blocks * 16]]
    previous_block[0] ^= ord(b'x') ^ ord(b';')
    previous_block[6] ^= ord(b'x') ^ ord(b'=')
    previous_block[11] ^= ord(b'x') ^ ord(b';')
    previous_block = bytes(previous_block)
    admin_string = encrypted[:(num_prefix_blocks - 1) * 16] + previous_block + encrypted[
                                                                                       num_prefix_blocks * 16:]
    return checker(admin_string)

if __name__ == '__main__':
    """Crypto Pals Set 2 #9"""
    #word = input("Enter a string to pad: ")
    #num = input("Enter the length to pad it to: ")
    #print(pkcs7pad(word, int(num)))

    """Crypto Pals Set 2 #10"""
    #b_string = b''.join([a2b_base64(line.strip()) for line in open("cryptopal10").readlines()])
    #for line in bytes_to_str(cbc_mode(b_string, b'YELLOW SUBMARINE', b'\x00'*16, encrypt=False)).split("\n")[:10]:
    #    print(line)

    """Crypto Pals Set 2 #11"""
    #msg = b"Yellow SubmarineTwo One Nine TwoYellow Submarine" * 2
    #ciphertext = encryption_oracle(msg)
    #print(f"Detected: {detect(ciphertext)} mode")

    """Crypto Pals Set 2 #12"""
    # detect block size
    #block_size = detect_block_size()
    #print(f"Block Size is {block_size}")

    # detect the mode (should be ECB)
    #repeated_plaintext = b"A" * 50
    #cipher = encryption_oracle(repeated_plaintext)
    #mode = detect_mode(cipher)
    #print(f"Mode of encryption is {mode}")

    # decrypt the plaintext inside `encryption_oracle()`
    #ecb_decrypt(block_size)

    """Crypto Pals Set 2 #13"""
    #create_admin_profile()

    """Crypto Pals Set 2 #14"""
    # detect block size
    #block_size = detect_block_size()
    #print(f"Block Size is {block_size}")

    # detect the mode (should be ECB)
    #repeated_plaintext = b"A" * 50
    #cipher = encryption_oracle(repeated_plaintext)
    #mode = detect_mode(cipher)
    #print(f"Mode of encryption is {mode}")

    # actual length of prefix
    #print(f"Actual size of prefix = {len(PREFIX)}")

    # decrypt the plaintext inside `encryption_oracle()`
    #ecb_decrypt(block_size)

    """Crypto Pals Set 2 #15"""
    #byte_string = b'ICE ICE BABY\x01\x02\x03\x04'
    #last_byte = byte_string[-1]
    #for i in range(last_byte, 0, -1):
    #    if byte_string[-i] != last_byte:
    #        raise ValueError("Bad padding")

    """Crypto Pals Set 2 #16"""
    #print(cbc_bitflipping_attack(cbc_bitflipping, cbc_bitflipping_check))
