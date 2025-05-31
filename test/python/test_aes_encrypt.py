import logging
from src.python.aes_encrypt import Cipher, KeyExpansion, Nk

def test_cipher():
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    KeyExpansion(key, Nk)

    # Input      = 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34 
    # Cipher Key = 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
    input1 = "3243f6a8885a308d313198a2e0370734"
    key1   = "2b7e151628aed2a6abf7158809cf4f3c"
    out1 = "3925841d02dc09fbdc118597196a0b32" # Appendix B
    assert(Cipher(input1, key1) == out1)

    input2 = "00112233445566778899aabbccddeeff"
    key2 = "000102030405060708090a0b0c0d0e0f"
    out2 = "69c4e0d86a7b0430d8cdb78070b4c55a" # Appendix C
    assert(Cipher(input2, key2) == out2)

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    test_cipher()