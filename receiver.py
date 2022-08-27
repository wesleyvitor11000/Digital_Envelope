from asyncio.windows_events import NULL
import base64
from email.policy import default
import string
from Crypto.Cipher import AES, DES, ARC4, PKCS1_OAEP
from tkinter import Tk
from tkinter.filedialog import askopenfilename
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

file_out = open("MensagemDecriptografada.bin", "wb")

def getInfosRSA(file_in):

    private_key = RSA.import_key(open("private.pem").read())
  
    content = file_in.read()
    content1 = str(content)
    
    i = 0
    st = ''
    ls = []

    for b in content1:
        if b == "=":
            i += 1

        st += b

        if i == 2:
            ls.append(st)
            st = ''
            i = 0

    ls.append(st)

    t = ls[0]
    ls[0] = t[2:]
    t = ls[len(ls) - 1]
    ls[len(ls) - 1] = t[:len(t) - 1]
   
    enc_session_key, nonce, tag, ciphertext = [base64.b64decode(x) for x in ls]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    return session_key, nonce, tag, ciphertext 


def decryptMessage(fileName, algorithm):

    file = open(fileName, "rb")

    session_key, nonce, tag, ciphertext = getInfosRSA(file)

    match algorithm:
        case '1':
            decryptAES(ciphertext, session_key, nonce, tag)
        case '2':
            decryptDES(ciphertext, session_key, nonce)
        case '3':
            decryptRC4(ciphertext, session_key)
        case _:
            print("invalid")

def decryptAES(encrypted, session_key, nonce, tag):
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    decrypted = cipher_aes.decrypt_and_verify(encrypted, tag)
    print(decrypted.decode("utf-8"))


def decryptDES(encrypted, session_key, nonce):
    cipher_des = DES.new(session_key, DES.MODE_EAX, nonce)
    decrypted = cipher_des.decrypt(encrypted)
    print(decrypted.decode("utf-8"))

def decryptRC4(encrypted, session_key):
    cipher_arc4 = ARC4.new(session_key)
    decrypted = cipher_arc4.decrypt(encrypted)
    print(decrypted.decode("utf-8"))


print('select file to decrypt:')
Tk().withdraw()
fileName = askopenfilename()
print('choose the algorithm:\n1 - AES \n2 - DES \n3 - RC4')
choice = input()
decryptMessage(fileName, choice)