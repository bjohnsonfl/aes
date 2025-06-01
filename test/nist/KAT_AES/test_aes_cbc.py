from pathlib import Path 
import pytest
import re

from src.python.aes_modes import aes_cbc
from scripts.rsp_parser import parse_kat_file

def get_kat_cbc_files(operation):
    kat_files = (list(Path("nist/KAT_AES").glob("CBC*.rsp")))
    tests = []
    for file in kat_files:
        kat_list = parse_kat_file(file)
        for (op, count), test in kat_list.items():
            if op == operation:
                tests.append((file, count, test))
    return tests

@pytest.mark.parametrize(("file, count, test"), get_kat_cbc_files("ENCRYPT"), ids=[f'{x[0].stem}_{x[2].operation}_{x[1]}' for x in get_kat_cbc_files("ENCRYPT")])
def test_kat_aes_cbc_encrypt(file, count, test):
    ct = aes_cbc(test.plaintext, test.key, test.iv, test.operation)
    assert(ct == test.ciphertext)

    # Swap PT and IV
    ct = aes_cbc(test.iv, test.key, test.plaintext, test.operation)
    assert(ct == test.ciphertext)


@pytest.mark.parametrize(("file, count, test"), get_kat_cbc_files("DECRYPT"), ids=[f'{x[0].stem}_{x[2].operation}_{x[1]}' for x in get_kat_cbc_files("DECRYPT")])
def test_kat_aes_cbc_decrypt(file, count, test):
    pt = aes_cbc(test.ciphertext, test.key, test.iv, test.operation)
    assert(pt == test.plaintext)

    # Swap CT and IV
    pt = aes_cbc(test.ciphertext, test.key, test.plaintext, test.operation)
    assert(pt == test.iv)