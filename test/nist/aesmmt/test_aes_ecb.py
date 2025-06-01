from pathlib import Path 
import pytest

from src.python.aes_modes import aes_ecb
from scripts.rsp_parser import parse_kat_file

def get_mmt_ecb_files(operation):
    mmt_files = (list(Path("nist/aesmmt").glob("ECB*.rsp")))
    tests = []
    for file in mmt_files:
        mmt_list = parse_kat_file(file)
        for (op, count), test in mmt_list.items():
            if op == operation:
                tests.append((file, count, test))
    return tests

@pytest.mark.parametrize(("file, count, test"), get_mmt_ecb_files("ENCRYPT"), ids=[f'{x[0].stem}_{x[2].operation}_{x[1]}' for x in get_mmt_ecb_files("ENCRYPT")])
def test_mmt_aes_ecb_encrypt(file, count, test):
    ct = aes_ecb(test.plaintext, test.key, test.operation)
    assert(ct == test.ciphertext)

@pytest.mark.parametrize(("file, count, test"), get_mmt_ecb_files("DECRYPT"), ids=[f'{x[0].stem}_{x[2].operation}_{x[1]}' for x in get_mmt_ecb_files("DECRYPT")])
def test_mmt_aes_ecb_decrypt(file, count, test):
    pt = aes_ecb(test.ciphertext, test.key, test.operation)
    assert(pt == test.plaintext)