from binascii import hexlify
from statistics import median
import requests

# HMAC is 20 bytes long
HMAC_LEN = 20

# Set 4 Challenge 31
# Guesses next byte of HMAC for filename w/ timing attack
# Done by getting avg of time taken by rounds requests to server
def get_next_byte(known_bytes, filename, rounds):
    # Num of zeroes to add to padding
    suffix_len = HMAC_LEN - len(known_bytes)

    # Initialize array counting request times for every possible byte
    times = [[] for _ in range(256)]

    # Each byte does rounds requests to find out which requests take longer
    for _ in range(rounds):

        # Try all possible bytes
        for i in range(256):
            suffix = bytes([i]) + (b'\x00' * (suffix_len - 1))
            signature = hexlify(known_bytes + suffix).decode()

            response = requests.get('http://localhost:8082/test?file=' + filename + '&signature=' + signature)

            # In case we found the correct signature already, return discovered
            if response.status_code == 200:
                return suffix

            times[i].append(response.elapsed.total_seconds())

    # Take median of requests times per byte
    median_times = [median(byte_times) for byte_times in times]

    # Get index of item which took highest median time for requests
    best = max(range(256), key=lambda b: median_times[b])

    return bytes([best])

# Does a timing attack on web server
def discover_mac_with_timing_attack(filename, rounds):
    print("Timing attack started.")

    # Get HMAC byte by byte
    known_bytes = b''
    while len(known_bytes) < HMAC_LEN:
        known_bytes += get_next_byte(known_bytes, filename, rounds)

        signature = hexlify(known_bytes).decode()
        print("Discovered so far:", signature)

    # Check if HMAC found is correct
    response = requests.get('http://localhost:8082/test?file=' + filename + '&signature=' + signature)

    if response.status_code == 200:
        print("\n> We made it! The HMAC is:", signature)
    else:
        print("\n> Unfortunately the attack did not work.")


if __name__ == "__main__":
    """CryptoPals Set4 #31"""
    # Took at least 32 hours to finish running
    # Make sure pals31web.py is running first
    # Correct HMAC for 'foo' = 8c80a95a8e72b3e822a13924553351a433e267d8
    discover_mac_with_timing_attack("foo", 10)