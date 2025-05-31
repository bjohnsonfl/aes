from dataclasses import dataclass
import logging

from aes_modes import aes_ecb

logger = logging.getLogger(__name__)

@dataclass
class BLOCK:
    block: int
    plaintext: str
    input: str
    output: str
    ciphertext: str

@dataclass
class TEST_CASE:
    plaintext: str
    ciphertext: str
    blocks: BLOCK
    key: str
    operation: str
    iv: str = None

ECB_AES128_plaintext  = "6bc1bee22e409f96e93d7e117393172a" \
                        "ae2d8a571e03ac9c9eb76fac45af8e51" \
                        "30c81c46a35ce411e5fbc1191a0a52ef" \
                        "f69f2445df4f9b17ad2b417be66c3710"
ECB_AES128_ciphertext = "3ad77bb40d7a3660a89ecaf32466ef97" \
                        "f5d3d58503b9699de785895a96fdbaaf" \
                        "43b1cd7f598ece23881b00e3ed030688" \
                        "7b0c785e27e8ad3f8223207104725dd4"

ECB_AES128_encrypt_blocks = [   BLOCK(1, "6bc1bee22e409f96e93d7e117393172a", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97", "3ad77bb40d7a3660a89ecaf32466ef97"),
                                BLOCK(2, "ae2d8a571e03ac9c9eb76fac45af8e51", "ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf", "f5d3d58503b9699de785895a96fdbaaf"),
                                BLOCK(3, "30c81c46a35ce411e5fbc1191a0a52ef", "30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688", "43b1cd7f598ece23881b00e3ed030688"),
                                BLOCK(4, "f69f2445df4f9b17ad2b417be66c3710", "f69f2445df4f9b17ad2b417be66c3710","7b0c785e27e8ad3f8223207104725dd4", "7b0c785e27e8ad3f8223207104725dd4")]

ECB_AES128_decrypt_blocks = [  BLOCK(1, "3ad77bb40d7a3660a89ecaf32466ef97", "3ad77bb40d7a3660a89ecaf32466ef97", "6bc1bee22e409f96e93d7e117393172a", "6bc1bee22e409f96e93d7e117393172a"),
                    BLOCK(2, "f5d3d58503b9699de785895a96fdbaaf", "f5d3d58503b9699de785895a96fdbaaf", "ae2d8a571e03ac9c9eb76fac45af8e51", "ae2d8a571e03ac9c9eb76fac45af8e51"),
                    BLOCK(3, "43b1cd7f598ece23881b00e3ed030688", "43b1cd7f598ece23881b00e3ed030688", "30c81c46a35ce411e5fbc1191a0a52ef", "30c81c46a35ce411e5fbc1191a0a52ef"),
                    BLOCK(4, "7b0c785e27e8ad3f8223207104725dd4", "7b0c785e27e8ad3f8223207104725dd4", "f69f2445df4f9b17ad2b417be66c3710", "f69f2445df4f9b17ad2b417be66c3710")]

ECB_AES128_test_cases = [TEST_CASE(ECB_AES128_plaintext, ECB_AES128_ciphertext, ECB_AES128_encrypt_blocks, "2b7e151628aed2a6abf7158809cf4f3c", "ENCRYPT"),
                         TEST_CASE(ECB_AES128_plaintext, ECB_AES128_ciphertext, ECB_AES128_decrypt_blocks, "2b7e151628aed2a6abf7158809cf4f3c", "DECRYPT")]


def test_aes_ecb_encrypt():
    for test in ECB_AES128_test_cases:
        if test.operation != "ENCRYPT":
            continue
        ct = aes_ecb(test.plaintext, test.key, "ENCRYPT")
        assert(test.ciphertext == ct)

def test_aes_ecb_decrypt():
    for test in ECB_AES128_test_cases:
        if test.operation != "DECRYPT":
            continue
        pt = aes_ecb(test.ciphertext, test.key, "DECRYPT")
        assert(test.plaintext == pt)

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    test_aes_ecb_encrypt()
    test_aes_ecb_decrypt()