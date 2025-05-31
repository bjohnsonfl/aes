import logging
from src.python.aes_decrypt import InvCipher

def test_decrypt_cipher():
    input1 = "69c4e0d86a7b0430d8cdb78070b4c55a"
    key1 = "000102030405060708090a0b0c0d0e0f"
    out1 = "00112233445566778899aabbccddeeff"
    assert(InvCipher(input1, key1) == out1)

    input_192 = "dda97ca4864cdfe06eaf70a0ec0d7191"
    key_192 = "000102030405060708090a0b0c0d0e0f1011121314151617"
    output_192 = "00112233445566778899aabbccddeeff"
    assert(InvCipher(input_192, key_192) == output_192)

    input_256 = "8ea2b7ca516745bfeafc49904b496089"
    key_256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    output_256 = "00112233445566778899aabbccddeeff"
    assert(InvCipher(input_256, key_256) == output_256)

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

    test_decrypt_cipher()