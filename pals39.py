from Cryptodome.Util.number import getPrime

# Set 5 Challenge 39
# Bunch of previously used functions
# Converts input int to bytes
def int_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

# Finds GCD w/ Euclidean Algorithm
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Finds LCM (least common multiple) of the two inputs, w/ GCD method
def lcm(a, b):
    return a // gcd(a, b) * b

# Finds multiplicative inverse of a mod n w/ ext euclidean algorithm
def mod_inv(a, n):
    t, r = 0, n
    new_t, new_r = 1, a
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        raise Exception("a is not invertible")
    if t < 0:
        t = t + n
    return t

# Class implementation of RSA public key
class RSA:
    # e fixed to 3 so we can find p & q to fit requirements
    def __init__(self, key_length):
        self.e = 3
        phi = 0
        while gcd(self.e, phi) != 1:
            p, q = getPrime(key_length // 2), getPrime(key_length // 2)
            phi = lcm(p - 1, q - 1)
            self.n = p * q
        self._d = mod_inv(self.e, phi)

    # Converts input bytes to int then encrypts w/ RSA
    def encrypt(self, binary_data):
        int_data = int.from_bytes(binary_data, byteorder='big')
        return pow(int_data, self.e, self.n)

    # Decrypts encrypted input to an int then converts to bytes
    def decrypt(self, encrypted_int_data):
        int_data = pow(encrypted_int_data, self._d, self.n)
        return int_to_bytes(int_data)


# Main Function
if __name__ == '__main__':
    """CryptoPals Set 5 #39"""
    # If assertions fail, program stops:
    # Check that implementation of mod inv is right
    assert mod_inv(17, 3120) == 2753
    print("Implementation of mod inv is correct.")

    # Check that implementation of RSA is right
    rsa = RSA(1024)
    some_text = b"Testing to see if RSA works"
    assert rsa.decrypt(rsa.encrypt(some_text)) == some_text
    print("Implementation of RSA is correct.")