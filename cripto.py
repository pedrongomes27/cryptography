from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode
from os import urandom
import json

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

# Exemplo de uso
if __name__ == "__main__":
    password = "minha_senha_secreta"

    # Criptografando um livro digital
    encrypt_file("livro_digital.pdf", "livro_digital_encrypted.pdf", password)

    # Descriptografando o livro digital
    decrypt_file("livro_digital_encrypted.pdf", "livro_digital_decrypted.pdf", password)

    # Criptografando uma música
    encrypt_file("musica.mp3", "musica_encrypted.mp3", password)

    # Descriptografando a música
    decrypt_file("musica_encrypted.mp3", "musica_decrypted.mp3", password)
