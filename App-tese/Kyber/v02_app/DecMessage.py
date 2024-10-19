import os
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def remove_pkcs7_padding(data):
    padding_length = data[-1]
    if padding_length > len(data):
        raise ValueError("Invalid padding")
    return data[:-padding_length]

def decrypt_message_with_aes(ciphertext, session_key):
    # Dividir o texto cifrado em IV e a mensagem cifrada
    iv = ciphertext[:16]  # O IV tem 16 bytes
    mensagem_cifrada = ciphertext[16:]  # O restante é a mensagem cifrada

    # Decifrar a mensagem
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(mensagem_cifrada) + decryptor.finalize()

    # Remover o preenchimento PKCS7
    unpadded_message = remove_pkcs7_padding(decrypted_message)
    return unpadded_message

