from pathlib import Path 
import pytest

from src.python.aes_modes import aes_cbc
from scripts.rsp_parser import parse_kat_file

def get_mmt_cbc_files():
    return list(Path("nist/aesmmt").glob("CBC*.rsp"))

@pytest.mark.parametrize("mmt_files", get_mmt_cbc_files(), ids=lambda p: p.name)
def test_mmt_aes_cbc_encrypt(mmt_files):
    mmt_list = parse_kat_file(mmt_files)
    for (op, count), value in mmt_list.items():
        if op == "ENCRYPT":
            ct = aes_cbc(value.plaintext, value.key, value.iv, op)
            assert(ct == value.ciphertext)

@pytest.mark.parametrize("mmt_files", get_mmt_cbc_files(), ids=lambda p: p.name)
def test_mmt_aes_cbc_decrypt(mmt_files):
    mmt_list = parse_kat_file(mmt_files)
    for (op, count), value in mmt_list.items():
        if op == "DECRYPT":
            pt = aes_cbc(value.ciphertext, value.key, value.iv, op)
            assert(pt == value.plaintext)