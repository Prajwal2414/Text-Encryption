from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os

def pad(text, block_size):
    return text + (block_size - len(text) % block_size) * chr(block_size - len(text) % block_size)

def unpad(text):
    return text[:-ord(text[-1])]

def aes_encrypt(text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_text = cipher.encrypt(pad(text, AES.block_size).encode())
    return base64.b64encode(encrypted_text).decode()

def aes_decrypt(encrypted_text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(base64.b64decode(encrypted_text)).decode())
    return decrypted_text

def des_encrypt(text, key):
    cipher = DES.new(key, DES.MODE_ECB)
    encrypted_text = cipher.encrypt(pad(text, DES.block_size).encode())
    return base64.b64encode(encrypted_text).decode()

def des_decrypt(encrypted_text, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(base64.b64decode(encrypted_text)).decode())
    return decrypted_text

def rsa_generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(text, public_key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_text = cipher_rsa.encrypt(text.encode())
    return base64.b64encode(encrypted_text).decode()

def rsa_decrypt(encrypted_text, private_key):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_text = cipher_rsa.decrypt(base64.b64decode(encrypted_text)).decode()
    return decrypted_text

def main():
    while True:
        print("\nChoose encryption method:")
        print("1. AES")
        print("2. DES")
        print("3. RSA")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            key = input("Enter a 16-byte key for AES: ").encode()
            text = input("Enter text to encrypt: ")
            encrypted = aes_encrypt(text, key)
            print("Encrypted:", encrypted)
            print("Decrypted:", aes_decrypt(encrypted, key))

        elif choice == '2':
            key = input("Enter an 8-byte key for DES: ").encode()
            text = input("Enter text to encrypt: ")
            encrypted = des_encrypt(text, key)
            print("Encrypted:", encrypted)
            print("Decrypted:", des_decrypt(encrypted, key))

        elif choice == '3':
            private_key, public_key = rsa_generate_keys()
            text = input("Enter text to encrypt: ")
            encrypted = rsa_encrypt(text, public_key)
            print("Encrypted:", encrypted)
            print("Decrypted:", rsa_decrypt(encrypted, private_key))

        elif choice == '4':
            break
        else:
            print("Invalid choice! Try again.")

if __name__ == "__main__":
    main()
