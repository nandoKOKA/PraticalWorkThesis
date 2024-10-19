import os
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

def decrypt_session_key_with_private_key(encrypted_session_key, private_key):
    try:
        # Decifrar a chave de sessão usando a chave privada
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

def save_session_key(session_key, save_location):
    try:
        with open(save_location, "wb") as file:
            file.write(session_key)
        print("Chave de sessão decifrada salva com sucesso em:", save_location)
    except Exception as e:
        print("Erro ao salvar a chave de sessão decifrada:", e)


