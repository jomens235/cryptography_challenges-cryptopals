from pals34 import is_pkcs7_padded, pkcs7_unpad
from pals34 import aes_cbc_encrypt, aes_cbc_decrypt
from pals34 import sha1
from Cryptodome import Random
from Cryptodome.Cipher import AES
from pals33 import DiffieHellman
from binascii import unhexlify

# Set 5 Challenge 35
# Simulates breaking the DH w/ groups with 'g'
def malicious_g_attack():
    p = DiffieHellman.DEFAULT_P

    for g in [1, p, p - 1]:
        # 1: MITM changes g sent to Bob w/ forced val
        alice = DiffieHellman()
        bob = DiffieHellman(g=g)

        # 2: Bob receives forced g and sends ACK back to Alice, simulated so it's blank

        # 3: Alice finds A and sends it to MITM according to Bob
        A = alice.get_public_key()

        # 4: Bob finds B and sends to MITM according to Alice
        B = bob.get_public_key()

        # 5: Alice sends encrypted msg to Bob without knowing MITM
        _msg = b'Hello, how are you?'
        _a_key = unhexlify(sha1(str(alice.get_shared_secret_key(B)).encode()))[:16]
        _a_iv = Random.new().read(AES.block_size)
        a_question = aes_cbc_encrypt(_msg, _a_key, _a_iv) + _a_iv

        # 6: Bob gets msg from Alice, without knowing about attack, again simulated to does nothing
        # Bob shouldn't be able to decrypt cause they have different g vals now

        # 7: MITM decrypts Alice's question
        mitm_a_iv = a_question[-AES.block_size:]

        # g = 1, secret key = 1
        if g == 1:
            mitm_hacked_key = unhexlify(sha1(b'1').encode())[:16]
            mitm_hacked_message = aes_cbc_decrypt(a_question[:-AES.block_size], mitm_hacked_key, mitm_a_iv)

        # if g = p, same attack as previous challenge (key 0)
        elif g == p:
            mitm_hacked_key = unhexlify(sha1(b'0').encode())[:16]
            mitm_hacked_message = aes_cbc_decrypt(a_question[:-AES.block_size], mitm_hacked_key, mitm_a_iv)

        # If g = p-1, key = (-1)^(ab), so either (1 % p) or (-1 % p)
        # Try both and check padding
        else:

            for candidate in [str(1).encode(), str(p - 1).encode()]:
                mitm_hacked_key = unhexlify(sha1(candidate).encode())[:16]
                mitm_hacked_message = aes_cbc_decrypt(a_question[:-AES.block_size], mitm_hacked_key,
                                                      mitm_a_iv, unpad=False)

                if is_pkcs7_padded(mitm_hacked_message):
                    mitm_hacked_message = pkcs7_unpad(mitm_hacked_message)
                    break

        # Check if attack worked
        assert _msg == mitm_hacked_message
        # Won't print line below if assertion fails
        print("The attack worked")

# Main Function
# Network part is simulated once again
if __name__ == '__main__':
    """CryptoPals Set 5 #35"""
    malicious_g_attack()
