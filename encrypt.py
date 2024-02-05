import sys
import argparse
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
import secrets
import time
from termcolor import colored

def generate_random_password(length=16):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=<>?"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def save_password_to_file(password, filename='password.txt'):
    with open(filename, 'w') as file:
        file.write(password)
    print(f'Password saved to {filename}')

def load_password_from_file(filename='password.txt'):
    with open(filename, 'r') as file:
        return file.read().strip()

def export_secret_to_file(secret, filename='exported_secret.txt'):
    with open(filename, 'w') as file:
        file.write(secret)
    print(f'Secret exported to {filename}')

def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_file(file_path, password, cipher='aes128'):
    salt = os.urandom(16)
    key = derive_key(password, salt)

    with open(file_path, 'rb') as file:
        plaintext = file.read()

    cipher_class = getattr(algorithms, cipher.upper(), None)
    if cipher_class is None:
        print('Invalid cipher specified. Supported ciphers are: aes128, aes192, aes256. Using default cipher aes128.')
        cipher_class = algorithms.AES

    cipher = Cipher(cipher_class(key), modes.CFB8(salt), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    encrypted_file_path = f"{file_path}.enc"
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(salt + ciphertext)

    print(f'File encrypted successfully: {encrypted_file_path}')
    return encrypted_file_path

def decrypt_file(encrypted_file_path, password, cipher='aes128'):
    with open(encrypted_file_path, 'rb') as encrypted_file:
        data = encrypted_file.read()

    salt, ciphertext = data[:16], data[16:]
    key = derive_key(password, salt)

    cipher_class = getattr(algorithms, cipher.upper(), None)
    if cipher_class is None:
        print('Invalid cipher specified. Supported ciphers are: aes128, aes192, aes256. Using default cipher aes128.')
        cipher_class = algorithms.AES

    cipher = Cipher(cipher_class(key), modes.CFB8(salt), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    decrypted_file_path = encrypted_file_path.removesuffix('.enc')
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(plaintext)

    print(f'File decrypted successfully: {decrypted_file_path}')
    return decrypted_file_path

def print_report(input_file, output_file, total_time, cipher):
    print(colored("\n---- Encryption/Decryption Report ----", 'cyan'))
    print(colored(f"Input File: {input_file}", 'cyan'))
    print(colored(f"Output File: {output_file}", 'cyan'))
    print(colored(f"Cipher: {cipher}", 'cyan'))
    print(colored(f"Total Time: {total_time:.4f} seconds", 'cyan'))

def process_files(file_paths, decrypt, export_secret, cipher='aes128'):
    for file_path in file_paths:
        print(colored(f"\nProcessing file: {file_path}", 'yellow'))

        # Generate and save a random password to a file
        random_password = generate_random_password()
        password_file = f"{file_path}_password.txt"
        save_password_to_file(random_password, password_file)

        # Export the password to a text file if specified
        if export_secret:
            export_secret_to_file(random_password)

        # Load the password from the file
        loaded_password = load_password_from_file(password_file)

        # Encrypt or decrypt based on the option
        start_time = time.time()
        if decrypt:
            output_file = decrypt_file(f"{file_path}.enc", loaded_password, cipher)
        else:
            output_file = encrypt_file(file_path, loaded_password, cipher)
        end_time = time.time()

        # Print the report for each file
        print_report(file_path, output_file, end_time - start_time, cipher)

def main():
    parser = argparse.ArgumentParser(description='Encrypt and decrypt files using a password')
    parser.add_argument('file_paths', nargs='+', type=str, help='Paths to the files to encrypt/decrypt')
    parser.add_argument('--password_length', type=int, default=16, help='Length of the random password (default: 16)')
    parser.add_argument('--decrypt', action='store_true', help='Specify if you want to decrypt the files')
    parser.add_argument('--export_secret', action='store_true', help='Export the generated passwords to text files')
    parser.add_argument('--cipher', type=str, default='aes128', help='Encryption cipher (default: aes128)')
    args = parser.parse_args()

    process_files(args.file_paths, args.decrypt, args.export_secret, args.cipher)

if __name__ == "__main__":
    main()
