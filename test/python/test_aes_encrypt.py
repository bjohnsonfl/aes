import logging
from src.python.aes_encrypt import Cipher, KeyExpansion

def test_cipher():
    keys = ["2b7e151628aed2a6abf7158809cf4f3c",
           "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
           "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"]
    for key in keys:
        key_len = len(key) * 4
        if key_len == 128:
            Nk = 4
            Nr = 10
        elif key_len == 192:
            Nk = 6
            Nr = 12
        elif key_len == 256:
            Nk = 8
            Nr = 14
        else:
            assert(0)
        KeyExpansion(key, Nk, Nr)

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

    input_192 = "00112233445566778899aabbccddeeff"
    key_192 = "000102030405060708090a0b0c0d0e0f1011121314151617"
    output_192 = "dda97ca4864cdfe06eaf70a0ec0d7191"
    assert(Cipher(input_192, key_192) == output_192)

    input_256 = "00112233445566778899aabbccddeeff"
    key_256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    output_256 = "8ea2b7ca516745bfeafc49904b496089"
    assert(Cipher(input_256, key_256) == output_256)
    
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    test_cipher()