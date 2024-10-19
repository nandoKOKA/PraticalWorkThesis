import os
import random
import string
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes


def generate_random_text_file(file_path, size_kb):
    with open(file_path, 'w') as f:
        random_text = ''.join(random.choices(string.ascii_letters + string.digits, k=size_kb * 1024))
        f.write(random_text)

def load_message_from_input(input_type='console', file_path=None):
    if input_type == 'console':
        mensagem = input("Digite a mensagem: ")
    elif input_type == 'file':
        try:
            with open(file_path, 'r') as file:
                mensagem = file.read()
        except FileNotFoundError:
            print(f"Arquivo não encontrado: {file_path}")
            mensagem = None
    else:
        print("Tipo de entrada inválido.")
        mensagem = None
    return mensagem

def pad_message(message):
    block_size = 16  # Tamanho do bloco em bytes (128 bits)
    padding_length = block_size - (len(message) % block_size)
    padding = bytes([padding_length]) * padding_length
    return message + padding

def encrypt_message_with_aes(message, key):
    if isinstance(message, str):
        message = message.encode("utf-8")
    padded_message = pad_message(message)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return iv + ciphertext

def encrypt_session_key_with_public_key(session_key, public_key):
    encrypted_session_key = public_key.encrypt(
        session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_session_key

def load_private_key_from_file(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def decrypt_session_key_with_private_key(encrypted_session_key, private_key):
    try:
        session_key = private_key.decrypt(
            encrypted_session_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return session_key
    except Exception as e:
        print("Erro ao decifrar a chave de sessão:", e)
        return None

def decrypt_message_with_aes(ciphertext, key):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    padding_length = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_length]
    return plaintext
