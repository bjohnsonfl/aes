![CI](https://github.com/bjohnsonfl/aes/actions/workflows/python-app.yaml/badge.svg?branch=main)

Docs:
- AES Spec
    * https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=901427
- AES Modes
    * https://csrc.nist.gov/Projects/block-cipher-techniques/BCM
    * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

IUT Tests:
Nist Test vectors
* https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES

```
python3 -m pip install pycryptodome pytest
PYTHONPATH=src pytest
```



