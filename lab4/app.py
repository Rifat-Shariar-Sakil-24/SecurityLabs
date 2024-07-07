import os
import sys
import time
import json
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256


DIR_KEYS = "enc_keys"
AES_KEY_FILE = 'key_aes.bin'
RSA_KEY_FILE = 'key_rsa.pem'
RSA_PUBLIC_KEY_FILE = 'rsa_pub.pem'
AES_MODE = {'ECB': AES.MODE_ECB, 'CFB': AES.MODE_CFB}


def aes_key_generate(bits):
   key = get_random_bytes((bits + 7) // 8)
   with open(os.path.join(DIR_KEYS, AES_KEY_FILE), 'wb') as f:
       f.write(key)
   return key


def rsa_key_generate(bits):
   key = RSA.generate(bits)
   key_private = key.export_key()
   key_public = key.publickey().export_key()
   with open(os.path.join(DIR_KEYS, RSA_KEY_FILE), 'wb') as f:
       f.write(key_private)
   with open(os.path.join(DIR_KEYS, RSA_PUBLIC_KEY_FILE), 'wb') as f:
       f.write(key_public)
   return key_private, key_public


def load_aes_key():
   with open(os.path.join(DIR_KEYS, AES_KEY_FILE), 'rb') as f:
       key = f.read()
   return key


def load_rsa_keys():
   with open(os.path.join(DIR_KEYS, RSA_KEY_FILE), 'rb') as f:
       private_key = RSA.import_key(f.read())
   with open(os.path.join(DIR_KEYS, RSA_PUBLIC_KEY_FILE), 'rb') as f:
       public_key = RSA.import_key(f.read())
   return private_key, public_key




def aes_encrypt(data, key, mode):
   cipher = AES.new(key, AES_MODE[mode])
   if mode == 'ECB':
       ciphertext = cipher.encrypt(pad(data, AES.block_size))
   else:
       iv = get_random_bytes(AES.block_size)
       cipher = AES.new(key, AES_MODE[mode], iv)
       ciphertext = iv + cipher.encrypt(data)
   return ciphertext


def aes_decrypt(ciphertext, key, mode):
   cipher = AES.new(key, AES_MODE[mode])
   if mode == 'ECB':
       plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
   else:
       iv = ciphertext[:AES.block_size]
       cipher = AES.new(key, AES_MODE[mode], iv)
       plaintext = cipher.decrypt(ciphertext[AES.block_size:])
   return plaintext


def rsa_encrypt(data, public_key):
   cipher = PKCS1_OAEP.new(public_key)
   return cipher.encrypt(data)


def rsa_decrypt(ciphertext, private_key):
   cipher = PKCS1_OAEP.new(private_key)
   return cipher.decrypt(ciphertext)


def rsa_sign(data, private_key):
   h = SHA256.new(data)
   signature = pkcs1_15.new(private_key).sign(h)
   return signature


def rsa_verify(data, signature, public_key):
   h = SHA256.new(data)
   try:
       pkcs1_15.new(public_key).verify(h, signature)
       return True
   except (ValueError, TypeError):
       return False


def sha256_hash(data):
   return hashlib.sha256(data).hexdigest()


def save_to_file(filename, data):
   with open(filename, 'wb') as f:
       f.write(data)


def read_from_file(filename):
   with open(filename, 'rb') as f:
       return f.read()




if __name__ == "__main__":
   if not os.path.exists(DIR_KEYS):
       os.makedirs(DIR_KEYS)


   print("Generating AES Keys...")
   key_length = int(input("Enter AES key length (128 or 256): "))
   aes_key_generate(key_length)
   print("AES Key Generated")
   print("Generating RSA Keys...")
   key_length = int(input("Enter RSA key length: "))
   _, public_key = rsa_key_generate(key_length)
   print("RSA Keys Generated")


   while True:
       print("\nSelect a functionality:")
       print("1) AES Encryption")
       print("2) AES Decryption")
       print("3) RSA Encryption")
       print("4) RSA Decryption")
       print("5) RSA Signature Generation")
       print("6) RSA Signature Verification")
       print("7) SHA-256 Hashing")
       print("8) Exit")




       choice = input("Enter your choice: ")




       if choice == '1':
           mode = input("Enter AES mode (ECB or CFB): ")
           data = input("Enter data to encrypt: ").encode()
           key = load_aes_key()
           start_time = time.time()
           encrypted_data = aes_encrypt(data, key, mode)
           elapsed_time = time.time() - start_time


           save_to_file('aes_encrypted.bin', encrypted_data)
           print(f"Encrypted data saved to 'aes_encrypted.bin'. Time taken: {elapsed_time:.4f} seconds")


       elif choice == '2':
           key = load_aes_key()
           mode = input("Enter AES mode (ECB or CFB): ")
           encrypted_data = read_from_file('aes_encrypted.bin')


           start_time = time.time()
           decrypted_data = aes_decrypt(encrypted_data, key, mode)
           elapsed_time = time.time() - start_time


           print(f"Decrypted data: {decrypted_data.decode()}")
           print(f"Time taken: {elapsed_time:.4f} seconds")


       elif choice == '3':
           data = input("Enter data to encrypt: ").encode()


           _, public_key = load_rsa_keys()
           start_time = time.time()
           encrypted_data = rsa_encrypt(data, public_key)
           elapsed_time = time.time() - start_time


           save_to_file('rsa_encrypted.bin', encrypted_data)
           print(f"Encrypted data saved to 'rsa_encrypted.bin'. Time taken: {elapsed_time:.4f} seconds")


       elif choice == '4':
           private_key, _ = load_rsa_keys()
           encrypted_data = read_from_file('rsa_encrypted.bin')


           start_time = time.time()
           decrypted_data = rsa_decrypt(encrypted_data, private_key)
           elapsed_time = time.time() - start_time


           print(f"Decrypted data: {decrypted_data.decode()}")
           print(f"Time taken: {elapsed_time:.4f} seconds")


       elif choice == '5':
           filename = input("Enter filename to sign: ")
           data = read_from_file(filename)
           private_key, _ = load_rsa_keys()


           start_time = time.time()
           signature = rsa_sign(data, private_key)
           elapsed_time = time.time() - start_time


           save_to_file(f"{filename}_rsa_signature.bin", signature)
           print(f"Signature saved to 'rsa_signature.bin'. Time taken: {elapsed_time:.4f} seconds")


       elif choice == '6':
           filename = input("Enter filename to verify: ")
           data = read_from_file(filename)
           signature = read_from_file(f"{filename}_rsa_signature.bin")
           _, public_key = load_rsa_keys()


           start_time = time.time()
           is_verified = rsa_verify(data, signature, public_key)
           elapsed_time = time.time() - start_time


           print(f"Verification: {'successful' if is_verified else 'failed'}")
           print(f"Time taken: {elapsed_time:.4f} seconds")


       elif choice == '7':
           filename = input("Enter filename to hash: ")
           data = read_from_file(filename)


           start_time = time.time()
           hash_value = sha256_hash(data)
           elapsed_time = time.time() - start_time


           print(f"SHA-256 Hash: {hash_value}")
           print(f"Time taken: {elapsed_time:.4f} seconds")


       elif choice == '8':
           break


       else:
           print("Invalid choice. Please try again.")
