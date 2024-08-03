import argparse
import os
from getpass import getpass
import base64
import shutil
from encryption import EncryptionContext, AESEncryption, KeyDerivation
from file_management import FileManagementModule
from key_management import KeyManagementModule

CONFIG_FILE = 'config.txt'
KEY_FILE = 'master_key.enc'

def setup_first_time():
    print("Welcome to the Secure File Storage System Setup")
    while True:
        master_password = getpass("Set a master password: ")
        confirm_password = getpass("Confirm master password: ")
        if master_password != confirm_password:
            print("Passwords do not match. Please try again.")
        else:
            break

    while True:
        storage_dir = input("Enter a directory to store encrypted files: ")
        if os.path.exists(storage_dir):
            choice = input("Directory already exists. Do you want to delete it or choose another name? (delete/another): ").strip().lower()
            if choice == 'delete':
                shutil.rmtree(storage_dir)
                os.makedirs(storage_dir)
                break
            elif choice == 'another':
                continue
            else:
                print("Invalid choice. Please try again.")
        else:
            os.makedirs(storage_dir)
            break

    key_management_module = KeyManagementModule(master_password)
    encrypted_master_key = key_management_module.encrypt_key(key_management_module.master_key)
    
    with open(CONFIG_FILE, 'w') as f:
        f.write(f'{storage_dir}\n')

    with open(KEY_FILE, 'wb') as f:
        f.write(encrypted_master_key)
    
    return key_management_module, storage_dir

def load_config():
    with open(CONFIG_FILE, 'r') as f:
        storage_dir = f.readline().strip()
    return storage_dir

def login():
    master_password = getpass("Enter master password: ")
    key_management_module = KeyManagementModule(master_password)
    
    with open(KEY_FILE, 'rb') as f:
        encrypted_master_key = f.read()
    
    try:
        decrypted_master_key = key_management_module.decrypt_key(encrypted_master_key)
        if decrypted_master_key == key_management_module.master_key:
            print("Login successful!")
            return key_management_module
        else:
            print("Incorrect password. Please try again.")
            return None
    except Exception as e:
        print(f"Login failed: {e}")
        return None

def process_command(args, key_management_module, file_management_module):
    if args.encrypt:
        file_path = args.encrypt
        with open(file_path, 'rb') as f:
            data = f.read()
        encrypted_data = key_management_module.encryption_context.encrypt(key_management_module.master_key, data)
        encrypted_file_name = base64.urlsafe_b64encode(key_management_module.encrypt_filename(os.path.basename(file_path)).encode()).decode() + '.enc'
        file_management_module.save_file(encrypted_file_name, encrypted_data)
        print(f'File {encrypted_file_name} encrypted and stored successfully.')
    
    elif args.decrypt:
        file_name = args.decrypt
        encrypted_file_name = base64.urlsafe_b64encode(key_management_module.encrypt_filename(file_name).encode()).decode() + '.enc'
        if encrypted_file_name in file_management_module.list_files():
            encrypted_data = file_management_module.read_file(encrypted_file_name)
            decrypted_data = key_management_module.encryption_context.decrypt(key_management_module.master_key, encrypted_data)
            decrypted_file_name = key_management_module.decrypt_filename(base64.urlsafe_b64decode(os.path.splitext(encrypted_file_name)[0]).decode())
            with open(decrypted_file_name, 'wb') as f:
                f.write(decrypted_data)
            print(f'File {decrypted_file_name} decrypted successfully.')
        else:
            print(f'File {file_name} not found.')
            
    elif args.list:
        files = file_management_module.list_files()
        print("Stored files:")
        for file in files:
            decrypted_file_name = key_management_module.decrypt_filename(base64.urlsafe_b64decode(os.path.splitext(file)[0]).decode())
            print(decrypted_file_name)

def main():
    if not os.path.exists(CONFIG_FILE) or not os.path.exists(KEY_FILE):
        key_management_module, storage_dir = setup_first_time()
    else:
        storage_dir = load_config()
        while True:
            key_management_module = login()
            if key_management_module:
                break

    file_management_module = FileManagementModule(storage_dir)

    while True:
        command = input("\nEnter command (encrypt, decrypt, list, exit): ").strip()
        if command == "exit":
            print("Exiting the Secure File Storage System. Goodbye!")
            break
        elif command == "encrypt" or command == "decrypt":
            file_name = input("Enter file name: ").strip()
            args = argparse.Namespace(encrypt=file_name if command == "encrypt" else None, 
                                      decrypt=file_name if command == "decrypt" else None, 
                                      list=False)
            process_command(args, key_management_module, file_management_module)
        elif command == "list":
            args = argparse.Namespace(encrypt=None, decrypt=None, list=True)
            process_command(args, key_management_module, file_management_module)
        else:
            print("Invalid command. Please try again.")
            print("Available commands: encrypt, decrypt, list, exit")

if __name__ == '__main__':
    main()
