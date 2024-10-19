from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Função para gerar uma hash SHA-256 de um arquivo
def generate_hash(file_path):
    with open(file_path, "rb") as file:
        file_content = file.read()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(file_content)
        return digest.finalize()

# Função para cifrar a hash usando RSA
def encrypt_hash(hash_value, public_key):
    cipher_text = public_key.encrypt(
        hash_value,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher_text

# Função para decifrar a hash usando RSA
def decrypt_hash(cipher_text, private_key):
    plain_text = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plain_text

# Carregar chave pública RSA de um arquivo
def load_public_key(file_path):
    with open(file_path, 'rb') as file:
        public_key = serialization.load_pem_public_key(
            file.read(),
            backend=default_backend()
        )
    return public_key

# Carregar a chave privada RSA de um arquivo
def load_private_key(file_path):
    with open(file_path, 'rb') as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

