import logging
from src.python.aes_decrypt import InvCipher

def test_decrypt_cipher():
    input1 = "69c4e0d86a7b0430d8cdb78070b4c55a"
    key1 = "000102030405060708090a0b0c0d0e0f"
    out1 = "00112233445566778899aabbccddeeff"
    assert(InvCipher(input1, key1) == out1)

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

    test_decrypt_cipher()