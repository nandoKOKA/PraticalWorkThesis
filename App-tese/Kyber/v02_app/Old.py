import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from Package import *
from Sign import *
from DecSessionKey import *
from DecMessage import *
from hash import *

def option_B():
    print("Bem-vindo ao sistema de envio seguro de mensagens!")

    # Caminhos para os arquivos fornecidos pelo usuário
    arquivo_excel_path = "/Users/tiagocarvalho/Desktop/App-tese/v02_app/random_excel_file.xlsx"
    arquivo_word_path = "/Users/tiagocarvalho/Desktop/App-tese/v02_app/random_word_file.docx"
    arquivo_pdf_path = "/Users/tiagocarvalho/Desktop/App-tese/v02_app/random_document.pdf"

    # Opções de tipo de arquivo
    print("Escolha o tipo de arquivo:")
    print("1: Excel (.xlsx)")
    print("2: Word (.docx)")
    print("3: PDF (.pdf)")

    escolha = int(input("Digite o número da opção desejada: "))
    if escolha not in [1, 2, 3]:
        print("Opção inválida.")
        return

    if escolha == 1:
        arquivo_path = arquivo_excel_path
        tipo_arquivo = "Excel (.xlsx)"
    elif escolha == 2:
        arquivo_path = arquivo_word_path
        tipo_arquivo = "Word (.docx)"
    elif escolha == 3:
        arquivo_path = arquivo_pdf_path
        tipo_arquivo = "PDF (.pdf)"

    print(f"Arquivo do tipo {tipo_arquivo} fornecido: {arquivo_path}")

    # Gerar uma chave AES aleatória
    aes_key = os.urandom(32)

    # Caminho para a chave privada do remetente
    private_key_file_path = "/Users/tiagocarvalho/Desktop/App-tese/v02_app/Sender/Sender_Keys/private_key_sender.pem"

    # Carregar a chave privada do remetente
    private_key = load_private_key(private_key_file_path)
    
    # Assinar o arquivo com a chave privada do remetente
    signature_file_path = "/Users/tiagocarvalho/Desktop/App-tese/v02_app/assinatura.bin"  
    sign_file_with_private_key(private_key, arquivo_path, signature_file_path)

    # Calcular a hash do arquivo original
    hash_original = generate_hash(arquivo_path)

    print("\nProcesso de envio concluído com sucesso!")

    # LADO DO DESTINATÁRIO
    continuar = input("Deseja prosseguir para o lado do destinatário? (s/n): ")
    if continuar.lower() == 's':

        # Caminho para a chave pública do remetente
        public_key_sender_path = '/Users/tiagocarvalho/Desktop/App-tese/v02_app/Publickeys/public_key_sender.pem'

        # Carregar a chave pública do remetente
        public_key_sender = load_public_key(public_key_sender_path)

        # Verificar a assinatura usando a chave pública do remetente
        if verify_file_signature(public_key_sender, arquivo_path, signature_file_path):
            print("A assinatura é válida.")

            # Cifrar a mensagem usando a chave AES
            mensagem_cifrada = encrypt_message_with_aes(arquivo_path, aes_key)
            
            # Salvar a mensagem cifrada em "ciphertext.txt"
            with open("ciphertext.txt", "wb") as file:
                file.write(mensagem_cifrada)

            # Caminho para a chave pública do destinatário
            public_key_path = '/Users/tiagocarvalho/Desktop/App-tese/v02_app/Publickeys/public_key_receptor.pem'

            # Carregar a chave pública do destinatário
            public_key = load_public_key(public_key_path)

            # Cifrar a chave AES com a chave pública do destinatário
            encrypted_session_key = encrypt_session_key_with_public_key(aes_key, public_key)

            # Salvar a chave de sessão cifrada em "encrypted_session_key.txt"
            with open("encrypted_session_key.txt", "wb") as file:
                file.write(encrypted_session_key)

            try:
                # Carregar a chave privada do destinatário
                with open("/Users/tiagocarvalho/Desktop/App-tese/v02_app/Receptor/Receptor_Keys/private_key_receptor.pem", "rb") as file:
                    private_key_recipient = serialization.load_pem_private_key(
                        file.read(),
                        password=None,
                        backend=default_backend()
                    )

                # Carregar a chave de sessão cifrada
                with open("encrypted_session_key.txt", "rb") as file:
                    encrypted_session_key = file.read()

                # Decifrar a chave de sessão com a chave privada do destinatário
                session_key = decrypt_session_key_with_private_key(encrypted_session_key, private_key_recipient)

                if session_key:
                    # Carregar o texto cifrado do arquivo
                    with open("ciphertext.txt", "rb") as file:
                        ciphertext = file.read()

                    # Decifrar a mensagem
                    mensagem_decifrada = decrypt_message_with_aes(ciphertext, session_key)

                    # Calcular a hash da mensagem decifrada
                    hash_decifrada = generate_hash(mensagem_decifrada)

                    # Perguntar se o destinatário deseja ver a mensagem original
                    ver_mensagem = input("Deseja ver a mensagem original? (s/n): ")
                    if ver_mensagem.lower() == 's':
                        # Decodificar a mensagem para UTF-8 e remover o prefixo 'b'
                        mensagem_original = mensagem_decifrada.decode('utf-8')
                        print("Mensagem original:", mensagem_original)
                    
                    # Verificar se as hashes são iguais
                    if hash_original == hash_decifrada:
                        print("A mensagem não foi alterada. A hash é igual à gerada inicialmente")
                    else:
                        print("!!!ATENÇÃO!!! A mensagem foi alterada. As hash's não são iguais.")
                else:
                    print("Não foi possível decifrar a chave de sessão.")
            except FileNotFoundError:
                print("Arquivo não encontrado.")
            except Exception as e:
                print("Ocorreu um erro:", e)
        else:
            print("A assinatura é inválida. Impossível continuar.")
            return

if __name__ == "__main__":
    option_B()
