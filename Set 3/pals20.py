from base64 import b64decode
from pals18 import ctr_mode, generate_random_bytes, crack_ctr_same_nonce
from Cryptodome.Cipher import AES

if __name__ == '__main__':
    """Crypto Pals Set 3 #20"""
    original_plaintexts = []
    ciphertexts = []
    random_key = generate_random_bytes(AES.key_size[0])

    # Reads in from file, contains list of encoded texts from website
    with open("cryptopal20") as f:
       for line in f:
            original_plaintext = b64decode(line)
            original_plaintexts.append(original_plaintext)
            ciphertexts.append(ctr_mode(original_plaintext, random_key, 0))

    cracked_plaintexts = crack_ctr_same_nonce(ciphertexts)

    # Basically same as #19
    for plaintext, original in zip(cracked_plaintexts, original_plaintexts):
        print(plaintext)
