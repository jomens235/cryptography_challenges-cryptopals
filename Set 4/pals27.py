from os.path import commonprefix
from pals25 import cbc_mode, pkcs7_padding, GLOBAL_KEY, BLOCK_SIZE, generate_random_bytes, fixed_xor

# Set 4 Challenge 27
# Rewritten function from Set 2
def cbc_url_encryptor(byte_string: bytes, encrypt=True)->bytes:
    if encrypt:
        prefix = b'comment1=cooking%20MCs;userdata='
        suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
        input_string = (prefix + byte_string + suffix).replace(b';', b'";"').replace(b'=', b'"="')
        return cbc_mode(pkcs7_padding(input_string, BLOCK_SIZE), GLOBAL_KEY, GLOBAL_KEY, encrypt=True)
    else:
        return cbc_mode(byte_string, GLOBAL_KEY, GLOBAL_KEY, encrypt=False)

# Checks if text is ASCII
def is_ascii_compliant(text):
    return all(x < 128 for x in text)

def cbc_url_encryptor_check(byte_string: bytes) -> bool:
    decrypted_string = cbc_url_encryptor(byte_string, encrypt=False)
    if not is_ascii_compliant(decrypted_string):
        raise ValueError(f"Not ASCII compliant", decrypted_string)

MAX_SIZE = 64
def find_block_size(encryptor):
    length_output = len(encryptor(b'A'*0))
    for i in range(1, MAX_SIZE):
        new_length_output = len(encryptor(b'A'*i))
        block_size = new_length_output - length_output
        if block_size != 0:
            break
        length_output = new_length_output
    return block_size

cbc_url_block_size = find_block_size(cbc_url_encryptor)

if __name__ == '__main__':
    """CryptoPals Set 4 #27"""
    byte_string = b"high ASCII here?"
    ciphertext = cbc_url_encryptor(byte_string)
    try:
        cbc_url_encryptor_check(ciphertext)
        print("No high ASCII")
    except ValueError as e:
        print(e)

    byte_string += bytes([129])
    ciphertext = cbc_url_encryptor(byte_string)
    try:
        cbc_url_encryptor_check(ciphertext)
        print("No high ASCII")
    except ValueError as e:
        print(e)

    print(cbc_url_block_size)
    plaintext = generate_random_bytes(cbc_url_block_size * 3)
    ciphertext = cbc_url_encryptor(plaintext)

    num_prefix_blocks = len(commonprefix([cbc_url_encryptor(b''),
                                          cbc_url_encryptor(b'A')])) // cbc_url_block_size + 1

    # Add extra letters so that prefix + extra = total blocks
    encrypted_strings = [cbc_url_encryptor(b'A' * 0)]
    min_addition = None
    for i in range(1, cbc_url_block_size):
        encrypted_strings.append(cbc_url_encryptor(b'A' * i))
        length_common_prefix = len(commonprefix(encrypted_strings))
        if length_common_prefix == num_prefix_blocks * cbc_url_block_size:
            min_addition = i - 1
            break
        encrypted_strings = [encrypted_strings[-1]]
    assert min_addition is not None

    len_prefix = num_prefix_blocks * cbc_url_block_size - min_addition
    print(len('comment1"="cooking%20MCs";"userdata"="') == len_prefix)

    ciphertext = ciphertext[len_prefix: cbc_url_block_size + len_prefix] + \
                 bytes([0] * cbc_url_block_size) + \
                 ciphertext[len_prefix: cbc_url_block_size + len_prefix]
    try:
        cbc_url_encryptor_check(ciphertext)
    except ValueError as e:
        modified_plaintext = e.args[1]
    IV = fixed_xor(modified_plaintext[:cbc_url_block_size],
                   modified_plaintext[2 * cbc_url_block_size:])
    print(IV == GLOBAL_KEY)
