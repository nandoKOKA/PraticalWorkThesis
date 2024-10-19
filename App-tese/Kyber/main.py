from kyber.ccakem import ccakem_generate_keys, ccakem_encrypt, ccakem_decrypt
import time
from colorama import Fore, Style
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from v02_app.Package import *
from v02_app.Sign import *
from v02_app.DecSessionKey import *
from v02_app.DecMessage import *
from v02_app.hash import *
from polynomials import *
from dilithium import *
from dilithium import Dilithium
from v02_app.Package import *
import getpass
from v02_app.Receptor.Receptor_Keys.Receptorkeys import generate_key_pair

def load_sender_credentials():
    # Defina as credenciais do emissor diretamente no código
    sender_credentials = {
        "user": "tiago@gmail.com",
        "password": "Emissor2024"
    }
    return sender_credentials

def load_receiver_credentials():
    # Defina as credenciais do receptor diretamente no código
    receiver_credentials = {
        "user": "joao@gmail.com",
        "password": "Recetor2024"
    }
    return receiver_credentials

def authenticate_sender():
    # Carregar as credenciais do emissor
    sender_credentials = load_sender_credentials()

    # Tentar autenticar até que as credenciais sejam válidas ou o usuário desista
    while True:
        # Solicitar nome de usuário
        username = input("Introduza o seu email: ")
        
        # Solicitar senha
        password = getpass.getpass("Introduza a password: ")

        # Verificar as credenciais
        if username == sender_credentials["user"] and password == sender_credentials["password"]:
            return True
        else:
            print(Fore.RED + "Password ou email errados. Por favor, tente novamente." + Style.RESET_ALL)

def authenticate_receiver(username, password):
    # Defina as credenciais do receptor diretamente no código
    receiver_credentials = {
        "user": "joao@gmail.com",
        "password": "Recetor2024"
    }
    if username == receiver_credentials["user"] and password == receiver_credentials["password"]:
        return True
    else:
        return False

def option_A():

    try:
        # Autenticar o emissor
        authenticated_sender = authenticate_sender()

        if authenticated_sender:            
            # Solicita ao usuário que insira a mensagem
            message = input("\nPor favor, insira a mensagem: ")

            # Inicializa a classe Dilithium com os parâmetros padrão
            dilithium = Dilithium(DEFAULT_PARAMETERS["dilithium2"])

            # Gera chave para assinatura
            chave_publica_sender, chave_privada_sender = dilithium.keygen()

            # Assina a mensagem
            assinatura = dilithium.sign(chave_privada_sender, message.encode())

            # Divide a mensagem em blocos de 32 bytes e preenche com espaços em branco se necessário
            message_blocks = [(message[i:i+32] + ' ' * (32 - len(message[i:i+32]))) for i in range(0, len(message), 32)]

            # Pergunta se o usuário deseja criptografar a mensagem
            encrypt_message = input("\nDeseja cifrar a mensagem? (sim/não): ")
            if encrypt_message.lower() == "sim":
                private_key_receptor, public_key_receptor = ccakem_generate_keys()
                ciphertext_blocks = []

                # Para cada bloco da mensagem
                for block in message_blocks:
                    # Encripta o bloco
                    ciphertext, shared_secret1 = ccakem_encrypt(public_key_receptor, block.encode('utf-8'))

                    # Adiciona o bloco criptografado à lista de blocos criptografados
                    ciphertext_blocks.append(ciphertext)

                # Pergunta se deseja prosseguir para o lado do destinatário
                proceed_to_receiver = input("\nDeseja prosseguir para o lado do destinatário? (sim/não): " )
                if proceed_to_receiver.lower() == "sim":
                    receptor_username = input("\nIntroduza o seu email: ")
                    receptor_password = getpass.getpass("Introduza a password: ")

                    # Autenticar o receptor
                    authenticated_receiver = authenticate_receiver(receptor_username, receptor_password)

                    if authenticated_receiver:
                        # Pergunta se deseja desencriptar a mensagem
                        decrypt_message = input("\nDeseja decifrar a mensagem? (sim/não): ")
                        if decrypt_message.lower() == "sim":
                            decrypted_blocks = []

                            # Captura o tempo de início da desencriptação
                            #start_decrypt_time = time.time()

                            # Para cada bloco criptografado
                            for ciphertext_block in ciphertext_blocks:
                                # Desencripta o bloco
                                decrypted_message, shared_secret2 = ccakem_decrypt(ciphertext_block, private_key_receptor)

                                # Adiciona o bloco desencriptado à lista de blocos desencriptados
                                decrypted_blocks.append(decrypted_message.decode('utf-8'))  # Convertendo de bytes para string

                            # Concatena os blocos desencriptados para obter a mensagem original
                            decrypted_message = ''.join(decrypted_blocks)

                            # Verifica a assinatura após descriptografar a mensagem
                            verificacao = dilithium.verify(chave_publica_sender, decrypted_message.strip(), assinatura)

                            # Exibe a mensagem original após desencriptação
                            print("\nMensagem recebida e decifrada:", decrypted_message.strip())  # Removendo espaços em branco extras

                            # Verifica se os segredos são iguais
                            print("\nSegredos são iguais?", shared_secret1 == shared_secret2)
                            assert shared_secret1 == shared_secret2
                            assert len(shared_secret1) == 32

                            # Verifica se a assinatura é válida
                            print("\nAssinatura é válida?", verificacao)
                            assert verificacao
                        else:
                            print("\nPrograma encerrado.")
                    else:
                        print("\nCredenciais inválidas para o receptor.")
                else:
                    print("\nPrograma encerrado.")
            else:
                print("\nPrograma encerrado.")
        else:
            print(Fore.RED + "\nCredenciais inválidas." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"\nOcorreu um erro: {e}" + Style.RESET_ALL)
    
def option_B():    
    try:
        # Autenticar o emissor
        authenticated_sender = authenticate_sender()

        if authenticated_sender:
            # Solicitar ao usuário que insira a mensagem
            mensagem = input("\nPor favor, insira a mensagem: ").encode('utf-8')

            # Perguntar se deseja criptografar a mensagem
            encrypt_message = input("\nDeseja cifrar a mensagem? (sim/não): ")
            if encrypt_message.lower() == "sim":
                # Assinar a mensagem
                private_key_file_path = "/Users/tiagocarvalho/Desktop/App-tese/Kyber/v02_app/Sender/Sender_Keys/private_key_sender.pem"
                private_key = load_private_key(private_key_file_path)
                signature = sign_message(private_key, mensagem)

                # Gerar uma chave AES aleatória
                aes_key = os.urandom(32)

                # Caminho para a chave pública do destinatário
                public_key_path = '/Users/tiagocarvalho/Desktop/App-tese/Kyber/v02_app/Publickeys/public_key_receptor.pem'
                public_key = load_public_key(public_key_path)

                # Cifrar a mensagem com a chave AES
                mensagem_cifrada = encrypt_message_with_aes(mensagem, aes_key)

                # Cifrar a chave AES com a chave pública do destinatário
                encrypted_session_key = encrypt_session_key_with_public_key(aes_key, public_key)

                # Salvar a mensagem cifrada em "ciphertext.txt"
                with open("ciphertext.txt", "wb") as file:
                    file.write(mensagem_cifrada)

                # Salvar a chave de sessão cifrada em "encrypted_session_key.txt"
                with open("encrypted_session_key.txt", "wb") as file:
                    file.write(encrypted_session_key)
            else:
                # Se não deseja criptografar, apenas assinar a mensagem
                private_key_file_path = "/Users/tiagocarvalho/Desktop/App-tese/Kyber/v02_app/Sender/Sender_Keys/private_key_sender.pem"
                private_key = load_private_key(private_key_file_path)
                signature = sign_message(private_key, mensagem)
                print("\nMensagem assinada com sucesso!")

            # Pergunta se deseja prosseguir para o lado do destinatário
            proceed_to_receiver = input("\nDeseja prosseguir para o lado do destinatário? (sim/não): ")
            if proceed_to_receiver.lower() == "sim":
                # Autenticar o receptor
                authenticated_receiver = False
                while not authenticated_receiver:
                    receptor_username = input("\nIntroduza o seu email: ")
                    receptor_password = getpass.getpass("Introduza a password: ")

                    authenticated_receiver = authenticate_receiver(receptor_username, receptor_password)

                    if not authenticated_receiver:
                        print("Credenciais inválidas para o receptor. Por favor, tente novamente.")
                        continue

                # Perguntar se deseja descriptografar a mensagem
                decrypt_message = input("\nDeseja decifrar a mensagem? (sim/não): ")
                if decrypt_message.lower() == "sim":
                    try:
                        # Carregar a chave privada do destinatário
                        with open("/Users/tiagocarvalho/Desktop/App-tese/Kyber/v02_app/Receptor/Receptor_Keys/private_key_receptor.pem", "rb") as file:
                            private_key_recipient = serialization.load_pem_private_key(
                                file.read(),
                                password=None,
                                backend=default_backend()
                            )

                        # Carregar a chave de sessão cifrada
                        with open("encrypted_session_key.txt", "rb") as file:
                            encrypted_session_key = file.read()

                        # Capturar o tempo de início da desencriptação
                        start_decrypt_time = time.time()

                        # Decifrar a chave de sessão com a chave privada do destinatário
                        session_key = decrypt_session_key_with_private_key(encrypted_session_key, private_key_recipient)

                        if session_key:
                            # Carregar o texto cifrado da mensagem
                            with open("ciphertext.txt", "rb") as file:
                                ciphertext = file.read()

                            # Decifrar a mensagem
                            mensagem_decifrada = decrypt_message_with_aes(ciphertext, session_key)

                            # Verificar a assinatura usando a chave pública do remetente
                            public_key_sender_path = '/Users/tiagocarvalho/Desktop/App-tese/Kyber/v02_app/Publickeys/public_key_sender.pem'
                            public_key_sender = load_public_key(public_key_sender_path)
                            if verify_signature(public_key_sender, mensagem_decifrada, signature):
                                # Decodificar a mensagem para UTF-8 e remover o prefixo 'b'
                                mensagem_original = mensagem_decifrada.decode('utf-8')
                                print("\nMensagem recebida e decifrada:", mensagem_original)
                                # Mensagem de verificação da assinatura
                                print("\nAssinatura válida!")
                            else:
                                print("\nA assinatura é inválida. Impossível continuar.")
                        else:
                            print("\nNão foi possível decifrar a chave de sessão.")
                    except FileNotFoundError:
                        print("Arquivo não encontrado.")
                    except Exception as e:
                        print("Ocorreu um erro:", e)
                else:
                    print("Encerrando o programa.")
            else:
                print("Encerrando o programa.")
        else:
            print("Encerrando o programa.")
    except Exception as e:
        print(Fore.RED + f"\nOcorreu um erro: {e}" + Style.RESET_ALL)

# Função principal
def main():
    print("\nBem-vindo! Você tem 2 opções: ")
    print("A. Criptografia Pós-Quântica")
    print("B. Criptografia Clássica")
    
    opcao = input("\nDigite a opção desejada (A ou B): ").upper()

    if opcao == "A":
        option_A()
    elif opcao == "B":
        option_B()
    else:
        print("Opção inválida. Por favor, escolha entre A ou B.")

if __name__ == "__main__":
    main()