from pathlib import Path
import re

from dataclasses import dataclass


@dataclass
class KAT_ENTRY:
    count: int = 0
    key: str = ""
    iv: str = None
    plaintext: str = ""
    ciphertext: str = ""
    operation: str = ""

def parse_kat_file(file_path):
    # Define pattern for "[Word] = [Value]"
    op_pattern = re.compile(r"^\[(DECRYPT|ENCRYPT)\]")
    field_pattern = re.compile(r'^(\w+)\s=\s(\w+)', re.MULTILINE)
    text = file_path.read_text()
    operation = "ENCRYPT" # Default, could change
    kat = {}

    count = ""

    for line in text.splitlines():
        # Determine if KAT's are Encryption or Decryption tests
        op_match = op_pattern.match(line)
        if op_match:
            operation = op_match.group(1)


        field_match = field_pattern.match(line)
        if field_match:
            word = field_match.group(1)
            value = field_match.group(2)
            if word == "COUNT":
                count = int(value)
                kat[operation, count] = KAT_ENTRY(count= count, operation= operation)
            elif word == "KEY":
                kat[operation, count].key=value
            elif word == "IV":
                kat[operation, count].iv=value
            elif word == "PLAINTEXT":
                kat[operation, count].plaintext=value
            elif word == "CIPHERTEXT":
                kat[operation, count].ciphertext=value
    return kat

def print_kat(kat):
    for (op, count), value in kat.items():
        print(f"op: {op}, count: {count}, Value: {value}")



def main():
    
    kat = parse_kat_file(Path("KAT_AES/CBCGFSbox128.rsp"))
    print_kat(kat)

if __name__ == "__main__":
    main()