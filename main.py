import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.simpledialog import askstring
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC
from os import urandom, makedirs
from os.path import dirname, join, exists

# Função para gerar uma chave a partir de uma senha
def generate_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Função para gerar um HMAC
def generate_hmac(key: bytes, data: bytes) -> bytes:
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

# Função para verificar um HMAC
def verify_hmac(key: bytes, data: bytes, hmac_to_verify: bytes):
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    h.verify(hmac_to_verify)

# Função para criptografar dados com HMAC
def encrypt(data: bytes, password: str) -> bytes:
    salt = urandom(16)  # Gera um salt aleatório
    key = generate_key_from_password(password, salt)
    iv = urandom(16)  # Vetor de inicialização (IV)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding dos dados para que sejam múltiplos do tamanho do bloco
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Gerar HMAC
    hmac = generate_hmac(key, encrypted_data)
    
    return salt + iv + encrypted_data + hmac

# Função para descriptografar dados com HMAC
def decrypt(encrypted_data: bytes, password: str) -> bytes:
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    hmac = encrypted_data[-32:]
    encrypted_data = encrypted_data[32:-32]
    key = generate_key_from_password(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Verificar HMAC
    verify_hmac(key, encrypted_data, hmac)

    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remoção do padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

# Função para criptografar um arquivo
def encrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, 'rb') as f:
        data = f.read()
    encrypted_data = encrypt(data, password)
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

# Função para descriptografar um arquivo
def decrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()
    data = decrypt(encrypted_data, password)
    with open(output_file, 'wb') as f:
        f.write(data)

# Funções para GUI
def select_file():
    file_path = filedialog.askopenfilename()
    entry_file_path.delete(0, tk.END)
    entry_file_path.insert(0, file_path)

def create_directory_if_not_exists(directory: str):
    if not exists(directory):
        makedirs(directory)

def encrypt_selected_file():
    file_path = entry_file_path.get()
    if not file_path:
        messagebox.showerror("Erro", "Nenhum arquivo selecionado")
        return
    password = askstring("Senha", "Digite a senha de criptografia:", show='*')
    if not password:
        return
    
    # Cria o diretório para arquivos criptografados se não existir
    encrypted_dir = join(dirname(file_path), "encrypted_files")
    create_directory_if_not_exists(encrypted_dir)

    output_file = join(encrypted_dir, file_path.split("/")[-1])
    encrypt_file(file_path, output_file, password)
    messagebox.showinfo("Sucesso", f"Arquivo criptografado salvo como {output_file}")

def decrypt_selected_file():
    file_path = entry_file_path.get()
    if not file_path:
        messagebox.showerror("Erro", "Nenhum arquivo selecionado")
        return
    password = askstring("Senha", "Digite a senha de descriptografia:", show='*')
    if not password:
        return
    
    # Cria o diretório para arquivos descriptografados se não existir
    decrypted_dir = join(dirname(file_path), "decrypted_files")
    create_directory_if_not_exists(decrypted_dir)

    output_file = join(decrypted_dir, file_path.split("/")[-1])
    try:
        decrypt_file(file_path, output_file, password)
        messagebox.showinfo("Sucesso", f"Arquivo descriptografado salvo como {output_file}")
    except Exception as e:
        messagebox.showerror("Erro", f"Falha ao descriptografar: {e}")

# Configuração da interface gráfica
root = tk.Tk()
root.title("Criptografia de Arquivos")

frame = tk.Frame(root, padx=10, pady=10)
frame.pack(padx=10, pady=10)

label_file_path = tk.Label(frame, text="Arquivo:")
label_file_path.grid(row=0, column=0, pady=(0, 10))

entry_file_path = tk.Entry(frame, width=50)
entry_file_path.grid(row=0, column=1, pady=(0, 10))

button_browse = tk.Button(frame, text="Selecionar", command=select_file)
button_browse.grid(row=0, column=2, padx=(10, 0), pady=(0, 10))

button_encrypt = tk.Button(frame, text="Criptografar", command=encrypt_selected_file)
button_encrypt.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(10, 0))

button_decrypt = tk.Button(frame, text="Descriptografar", command=decrypt_selected_file)
button_decrypt.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(10, 0))

root.mainloop()
