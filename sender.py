from asyncio.windows_events import NULL
from email.policy import default
from statistics import mode
from Crypto.Cipher import AES, DES, ARC4, PKCS1_OAEP
from tkinter import Tk
from tkinter.filedialog import askopenfilename, asksaveasfilename
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import base64

def encryptRSA(cipher_rsa, key, encryptedKeyFileName, nonce = NULL, tag = NULL):
    print("Encriptando chave")
    enc_session_key = cipher_rsa.encrypt(key)

    key_out = open(encryptedKeyFileName, "wb")

    ls = [enc_session_key]
    if not nonce == NULL:
        ls.append(nonce)

    if not tag == NULL:
        ls.append(tag)

    [key_out.write(base64.b64encode(x)) for x in ls ]
    key_out.close()


def encryptMessage(fileName, publicKey, encryptedFileName, encryptedKeyFileName, algorithm):

    file = open(fileName, "rb")
    recipient_key = RSA.import_key(open(publicKey).read())
    
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    content = file.read()
    encrypted = ""

    print("Encriptando mensagem...")
    match algorithm:
        case '1':
            encrypted = encryptAES(content, cipher_rsa, encryptedKeyFileName)
        case '2':
            encrypted = encryptDES(content, cipher_rsa, encryptedKeyFileName)
        case '3':
            encrypted = encryptRC4(content, cipher_rsa, encryptedKeyFileName)
        case _:
            print("invalid")

    file_out = open(encryptedFileName, "wb")
    file_out.write(base64.b64encode(encrypted))
    file_out.close()

def encryptAES(content, cipher_rsa, encryptedKeyFileName):

    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    encrypted, tag = cipher.encrypt_and_digest(content)
    encryptRSA(cipher_rsa, key, encryptedKeyFileName, cipher.nonce, tag)

    return encrypted


def encryptDES(content, cipher_rsa, encryptedKeyFileName):

    key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_EAX)
    encrypted = cipher.encrypt(content)
    encryptRSA(cipher_rsa, key, encryptedKeyFileName, cipher.nonce)

    return encrypted

def encryptRC4(content, cipher_rsa, encryptedKeyFileName):
    key = get_random_bytes(16)
    cipher = ARC4.new(key)
    encrypted = cipher.encrypt(content)
    encryptRSA(cipher_rsa, key, encryptedKeyFileName)

    return encrypted

print("Selecione o arquivo para encriptar:")
Tk().withdraw()
fileName = askopenfilename()

print("Selecione a chave publica do destinatario:")
publicKey = askopenfilename()

print("Salvar mensagem criptografada como:")
cryptedName = asksaveasfilename()

print("Salvar chave criptografada como:")
cryptedKeyName = asksaveasfilename()

print("Escolha o algoritmo de encriptação:\n1 - AES \n2 - DES \n3 - RC4")
choice = input()

encryptMessage(fileName, publicKey, cryptedName, cryptedKeyName, choice)
print("pronto!")