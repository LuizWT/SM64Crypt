import os
import base64
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from colorama import init, Fore, Style

init(autoreset=True)

SCRIPT_PATH = os.path.abspath(__file__)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(file_path, password):
    if file_path == SCRIPT_PATH or file_path.endswith(".sm64"):
        return  # Evita criptografar o próprio script e arquivos já criptografados

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        salt = os.urandom(16)
        key = derive_key(password, salt)
        fernet = Fernet(key)

        encrypted_data = fernet.encrypt(data)
        output_data = salt + encrypted_data

        encrypted_file = file_path + ".sm64"

        with open(encrypted_file, "wb") as f:
            f.write(output_data)

        os.remove(file_path)  # Remove o arquivo original

        print(f"Arquivo criptografado e original removido: '{encrypted_file}'")
    except Exception as e:
        print(f"Erro ao criptografar '{file_path}':", e)

def decrypt_file(file_path, password):
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()

        salt = file_data[:16]
        encrypted_data = file_data[16:]
        key = derive_key(password, salt)
        fernet = Fernet(key)

        decrypted_data = fernet.decrypt(encrypted_data)

        original_file = file_path[:-5]

        with open(original_file, "wb") as f:
            f.write(decrypted_data)

        os.remove(file_path)  # Remove o arquivo criptografado

        print(f"Arquivo descriptografado e original restaurado: '{original_file}'")
    except InvalidToken:
        print(f"Senha incorreta ou arquivo corrompido: '{file_path}'")
    except Exception as e:
        print(f"Erro ao descriptografar '{file_path}':", e)

def encrypt_folder(folder_path):
    password = getpass.getpass("Digite a senha para criptografia: ")

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, password)

def decrypt_folder(folder_path):
    password = getpass.getpass("Digite a senha para descriptografia: ")

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".sm64"):
                file_path = os.path.join(root, file)
                decrypt_file(file_path, password)

def menu():
    current_directory = os.getcwd()
    
    title = r"""
   _____ __  __   __ _  _    _____                  _   
  / ____|  \/  | / /| || |  / ____|                | |  
 | (___ | \  / |/ /_| || |_| |     _ __ _   _ _ __ | |_ 
  \___ \| |\/| | '_ \__   _| |    | '__| | | | '_ \| __|
  ____) | |  | | (_) | | | | |____| |  | |_| | |_) | |_ 
 |_____/|_|  |_|\___/  |_|  \_____|_|   \__, | .__/ \__|
                                         __/ | |        
                                        |___/|_|        
 
    """
    print(Fore.CYAN + title + Style.RESET_ALL)

    while True:
        print(f"{Fore.GREEN}Diretório atual:{Style.RESET_ALL} {Fore.YELLOW}{current_directory}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}1.{Style.RESET_ALL} Criptografar todos os arquivos da pasta atual (incluindo subpastas)")
        print(f"{Fore.MAGENTA}2.{Style.RESET_ALL} Descriptografar todos os arquivos da pasta atual (incluindo subpastas)")
        print(f"{Fore.MAGENTA}3.{Style.RESET_ALL} Sair")

        choice = input(f"\n{Fore.BLUE}Selecione uma opção:{Style.RESET_ALL} ")

        if choice == "1":
            encrypt_folder(current_directory)
        elif choice == "2":
            decrypt_folder(current_directory)
        elif choice == "3":
            print(f"{Fore.RED} 'Saindo...' {Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED} 'Opção inválida. Tente novamente.' {Style.RESET_ALL}")

if __name__ == "__main__":
    menu()
