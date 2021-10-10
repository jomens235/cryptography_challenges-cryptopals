from pals31 import discover_mac_with_timing_attack


if __name__ == '__main__':
    """CryptoPals Set 4 #32"""
    # Change rounds value in function call and delay val in server to adjust timing
    # Again, make sure server is running
    # Correct HMAC for 'foo' = 8c80a95a8e72b3e822a13924553351a433e267d8
    discover_mac_with_timing_attack("foo", 5)