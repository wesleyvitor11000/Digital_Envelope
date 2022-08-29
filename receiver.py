from asyncio.windows_events import NULL
import base64
from email.policy import default
from Crypto.Cipher import AES, DES, ARC4, PKCS1_OAEP
from tkinter import Tk
from tkinter.filedialog import askopenfilename, asksaveasfilename
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

def decryptRSA(enc_session_key, privateKeyFileName):
    print("Decriptando chave...")
    private_key = RSA.import_key(open(privateKeyFileName).read())
    
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    return session_key

def getInfosRSA(file_in):

    content = file_in.read()
    content1 = str(content)

    content1 = content1.removeprefix('b\'').removesuffix('=\'')
    results = [result.__add__("==") for result in content1.split("==")]
    results = [base64.b64decode(result) for result in results]

    while len(results) < 3:
        results.append("")

    return results


def decryptMessage(fileName, keyFileName, privateKeyFile, outputFile, algorithm):

    encrypted_key = open(keyFileName, "rb")
    encrypted_message = open(fileName, "rb")

    session_key_result = getInfosRSA(encrypted_key)
    session_key, nonce, tag = session_key_result
    session_key = decryptRSA(session_key, privateKeyFile)

    crypted_text = getInfosRSA(encrypted_message)[0]

    decrypted = ""

    print("Decriptando mensagem...")
    match algorithm:
        case '1':
            decrypted = decryptAES(crypted_text, session_key, nonce, tag)
        case '2':
            decrypted = decryptDES(crypted_text, session_key, nonce)
        case '3':
            decrypted = decryptRC4(crypted_text, session_key)
        case _:
            print("invalid")
            return
    
    output = open(outputFile, "w")
    output.write(decrypted)

def decryptAES(encrypted, session_key, nonce, tag):
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    decrypted = cipher_aes.decrypt_and_verify(encrypted, tag)
    return decrypted.decode("utf-8")


def decryptDES(encrypted, session_key, nonce):
    cipher_des = DES.new(session_key, DES.MODE_EAX, nonce)
    decrypted = cipher_des.decrypt(encrypted)
    return decrypted.decode("utf-8")

def decryptRC4(encrypted, session_key):
    cipher_arc4 = ARC4.new(session_key)
    decrypted = cipher_arc4.decrypt(encrypted)
    return decrypted.decode("utf-8")


print('Selecione o arquivo para decriptar:')
Tk().withdraw()
fileName = askopenfilename()

print('Selecione a arquivo da chave encriptada:')
Tk().withdraw()
encryptedKeyFile = askopenfilename()

print('Selecione o arquivo da chave privada:')
Tk().withdraw()
privateKeyFile = askopenfilename()

print("Salvar mensagem decriptada como:")
cryptedName = asksaveasfilename()

print('Escolha o algoritmo para a encriptação:\n1 - AES \n2 - DES \n3 - RC4')
choice = input()
decryptMessage(fileName, encryptedKeyFile, privateKeyFile, cryptedName, choice)
print("ponto")