import random

# Set 3 Challenge 23:
# Returns lowest num of bits of first parameter
def get_lowest_bits(n, number_of_bits):
    mask = (1 << number_of_bits) - 1
    return n & mask

# Basically same as Wikipedia Pseudocode
class MT19937:
    W, N, M, R = 32, 624, 397, 31
    A = 0x9908B0DF
    U, D = 11, 0xFFFFFFFF
    S, B = 7, 0x9D2C5680
    T, C = 15, 0xEFC60000
    L = 18
    F = 1812433253
    LOWER_MASK = (1 << R) - 1
    UPPER_MASK = get_lowest_bits(not LOWER_MASK, W)

    def __init__(self, seed):
        self.mt = []

        self.index = self.N
        self.mt.append(seed)
        for i in range(1, self.index):
            self.mt.append(get_lowest_bits(self.F * (self.mt[i - 1] ^ (self.mt[i - 1] >> (self.W - 2))) + i, self.W))

    def extract_number(self):
        if self.index >= self.N:
            self.twist()

        y = self.mt[self.index]
        y ^= (y >> self.U) & self.D
        y ^= (y << self.S) & self.B
        y ^= (y << self.T) & self.C
        y ^= (y >> self.L)

        self.index += 1
        return get_lowest_bits(y, self.W)

    def twist(self):
        for i in range(self.N):
            x = (self.mt[i] & self.UPPER_MASK) + (self.mt[(i + 1) % self.N] & self.LOWER_MASK)
            x_a = x >> 1
            if x % 2 != 0:
                x_a ^= self.A

            self.mt[i] = self.mt[(i + self.M) % self.N] ^ x_a

        self.index = 0

# Returns bit at the position of the given num. Starts from left
def get_bit(number, position):
    if position < 0 or position > 31:
        return 0
    return (number >> (31 - position)) & 1

# Sets bit at given position to 1. Also starts from left
def set_bit_to_one(number, position):
    return number | (1 << (31 - position))

# Undoes right shift and XOR
def undo_right_shift_xor(result, shift_len):
    original = 0
    for i in range(32):
        next_bit = get_bit(result, i) ^ get_bit(original, i - shift_len)
        if next_bit == 1:
            original = set_bit_to_one(original, i)

    return original

# Undoes left shift and XOR
def undo_left_shift_xor_and(result, shift_len, andd):
    original = 0
    for i in range(32):
        next_bit = get_bit(result, 31 - i) ^ \
                   (get_bit(original, 31 - (i - shift_len)) &
                    get_bit(andd, 31 - i))

        if next_bit == 1:
            original = set_bit_to_one(original, 31 - i)
    return original

# Undoes the tampering process and returns initial value state of RNG
def untemper(y):
    y = undo_right_shift_xor(y, MT19937.L)
    y = undo_left_shift_xor_and(y, MT19937.T, MT19937.C)
    y = undo_left_shift_xor_and(y, MT19937.S, MT19937.B)
    y = undo_right_shift_xor(y, MT19937.U)
    return y

# Untempers each RNG output and splices them into the new cloned instance
def get_cloned_rng(original_rng):
    mt = []

    # Recreate the state of original_rng
    for i in range(MT19937.N):
        mt.append(untemper(original_rng.extract_number()))

    # Create new gen, set it to have same state
    cloned_rng = MT19937(0)
    cloned_rng.mt = mt
    return cloned_rng

if __name__ == '__main__':
    """Crypto Pals Set 3 #23"""
    seed = random.randint(0, 2 ** 32 - 1)
    rng = MT19937(seed)
    cloned_rng = get_cloned_rng(rng)

    # Check that the two PRNGs produce the same output now
    for i in range(1000):
        assert rng.extract_number() == cloned_rng.extract_number()
    print(rng.extract_number(), " & ", cloned_rng.extract_number())
