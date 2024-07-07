# Lab 4 Report





## Prerequisites

open terminal and install pycryptodome

```sh
pip install pycryptodome
```
### Generating AES Key
For encryption and decryption, we need to generate an AES key. That’s why for 128 bits we create an AES key named aes_key.bin.

```sh
def aes_key_generate(bits):
   key = get_random_bytes((bits + 7) // 8)
   with open(os.path.join(DIR_KEYS, AES_KEY_FILE), 'wb') as f:
       f.write(key)
   return key
```

###

