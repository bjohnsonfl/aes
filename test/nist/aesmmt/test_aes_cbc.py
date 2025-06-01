from pathlib import Path 
import pytest

from src.python.aes_modes import aes_cbc
from scripts.rsp_parser import parse_kat_file

def get_mmt_cbc_files(operation):
    mmt_files = (list(Path("nist/aesmmt").glob("CBC*.rsp")))
    tests = []
    for file in mmt_files:
        mmt_list = parse_kat_file(file)
        for (op, count), test in mmt_list.items():
            if op == operation:
                tests.append((file, count, test))
    return tests

@pytest.mark.parametrize(("file, count, test"), get_mmt_cbc_files("ENCRYPT"), ids=[f'{x[0].stem}_{x[2].operation}_{x[1]}' for x in get_mmt_cbc_files("ENCRYPT")])
def test_mmt_aes_cbc_encrypt(file, count, test):
    ct = aes_cbc(test.plaintext, test.key, test.iv, test.operation)
    assert(ct == test.ciphertext)

@pytest.mark.parametrize(("file, count, test"), get_mmt_cbc_files("DECRYPT"), ids=[f'{x[0].stem}_{x[2].operation}_{x[1]}' for x in get_mmt_cbc_files("DECRYPT")])
def test_mmt_aes_cbc_decrypt(file, count, test):
    pt = aes_cbc(test.ciphertext, test.key, test.iv, test.operation)
    assert(pt == test.plaintext)