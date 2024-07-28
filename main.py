# TODO:
# Write a file encryption-decryption software that requires a password
# Using any library is suffice
# We used: https://cryptography.io/en/latest/fernet/

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64
from cryptography.fernet import Fernet
from dotenv import load_dotenv


def create_key(password: str, salt) -> Fernet:
    # Because you can't use KDF twice for some reason
    """This function creates and use a kdf key which has SHA256

    Args:
        password (str): The password string
        salt (_type_): The salting value

    Returns:
        Fernet: A Cryptographic Fernet key instance
    """
    bpassword = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=16000
    )
    key = base64.urlsafe_b64encode(kdf.derive(bpassword))
    return Fernet(key=key)


def strip_empty_lines(data: list[str]) -> list[str]:
    """This function removes what would otherwise be empty lines of no significant value

    Args:
        data (list[str]): List of string read from file readlines()

    Returns:
        data (list[str]): The same list after the operation
    """
    for line in data:
        if line == '\n':
            data.remove(line)
    return data


def encrypt_str_list(data: list[str], fernet: Fernet) -> list[str]:
    """Convert the list of String to encrypted list of String for writing to file

    Args:
        data (list[str]): Pre-Encrypted Text
        fernet (Fernet): Fernet instance 

    Returns:
        list[str]: List of encoded string
    """
    encrypted_list = []
    for item in data:
        encrypt = fernet.encrypt(item.encode())
        encrypted_list.append(encrypt.decode())
        encrypted_list.append('\n')
    return encrypted_list


# Load data and ignore empty lines:
def encrypt_file(file_name, encrypted_file_name, password, salt):
    with open(file_name, 'r') as f:
        data = f.readlines()

    data = strip_empty_lines(data=data)

    # Encryption
    encryption_key = create_key(password=password, salt=salt)
    encrypted_data = encrypt_str_list(data, encryption_key)

    # Write to File
    with open(encrypted_file_name, 'w') as f:
        f.writelines(encrypted_data)


def decrypt_file(encrypted_file_name, password, decrypted_file_name, salt):
    with open(encrypted_file_name, 'r') as f:
        data = f.readlines()

    data = strip_empty_lines(data=data)
    decryption_key = create_key(password=password, salt=salt)

    temp = []
    for line in data:
        temp.append(line.removesuffix('\n'))

    data = temp

    temp = []
    for line in data:
        temp.append(line.encode())

    data = temp

    decrypted = []
    for line in data:
        try:
            decrypted.append(decryption_key.decrypt(line).decode())
        except:
            decrypted.append("ERROR, SKIPPING...\n")

    with open(decrypted_file_name, 'w') as f:
        f.writelines(decrypted)


def main():
    input_dir = './input/'
    output_dir = './output/'
    
    
    # salt = os.urandom(16) # TODO: Workaround for storage maybe (random everytime hence the Failure)
    load_dotenv()

    # Salt looks something along the line of:
    # 8f2b5c3e7d9a1f4b6c8e2a7d9f0b3c5d
    salt = os.getenv('SALT')
    salt = salt.encode()

    # Main
    while (True):
        print("Choose Mode (1: Encrypt a file, 2: Decrypt an Encrypted File, Else: Exit): ")
        mode = int(input("Select Mode: "))
        print(mode)
        # Mode 1
        if mode == 1:
            print('-------------')
            file_name_raw = str(input("Select file to encrypt: "))
            encrypted_file_name_raw = str(
                input("Select encrypted file's name: "))
            epassword = str(input("Create Password: "))

            file_name = input_dir + file_name_raw
            encrypted_file_name = output_dir + encrypted_file_name_raw

            encrypt_file(file_name, encrypted_file_name,
                         password=epassword, salt=salt)
            break

        # Mode 2
        elif mode == 2:
            print('-------------')
            encrypted_file_name_raw = str(input("Select file to Decrypt: "))
            decrypted_file_name_raw = str(
                input("Select decrypted file's name: "))

            mpassword = str(input("Input password: "))

            encrypted_file_name = output_dir + encrypted_file_name_raw
            decrypted_file_name = output_dir + decrypted_file_name_raw

            decrypt_file(encrypted_file_name, password=mpassword,
                         decrypted_file_name=decrypted_file_name, salt=salt)
            break
        else:
            break


if __name__ == '__main__':
    main()
