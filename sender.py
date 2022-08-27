from asyncio.windows_events import NULL
from email.policy import default
from Crypto.Cipher import AES, DES, ARC4, PKCS1_OAEP
from tkinter import Tk
from tkinter.filedialog import askopenfilename
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import base64

key = RSA.generate(2048)
private_key = key.export_key()
file_out = open("private.pem", "wb")
file_out.write(private_key)
file_out.close()

public_key = key.publickey().export_key()
file_out_key = open("receiver.pem", "wb")
file_out_key.write(public_key)
file_out_key.close() 

file_out = open("MensagemCriptografada.bin", "wb")
recipient_key = RSA.import_key(open("receiver.pem").read())

def encryptMessage(fileName, receiverKey, algorithm):

    file = open(fileName, "rb")
    content = file.read()

    match algorithm:
        case '1':
            encryptAES(content)
        case '2':
            encryptDES(content)
        case '3':
            encryptRC4(content)
        case _:
            print("invalid")

def encryptAES(content):

    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    encrypted, tag = cipher.encrypt_and_digest(content)
    enc_session_key = cipher_rsa.encrypt(key)

    [ file_out.write(base64.b64encode(x)) for x in (enc_session_key, cipher.nonce, tag, encrypted) ]
    file_out.close()


def encryptDES(content):

    key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_EAX)
    encrypted = cipher.encrypt(content)
    enc_session_key = cipher_rsa.encrypt(key)

    [ file_out.write(base64.b64encode(x)) for x in (enc_session_key, cipher.nonce, b"\n", encrypted) ]
    file_out.close()

def encryptRC4(content):
    key = get_random_bytes(16)
    cipher_arc4 = ARC4.new(key)
    ciphertext = cipher_arc4.encrypt(content)
    enc_session_key = cipher_rsa.encrypt(key)

    [ file_out.write(base64.b64encode(x)) for x in (enc_session_key, b"\n", b"\n", ciphertext) ]
    file_out.close()

print('select file to encrypt:')
Tk().withdraw()
fileName = askopenfilename()
print('choose the algorithm:\n1 - AES \n2 - DES \n3 - RC4')
choice = input()
cipher_rsa = PKCS1_OAEP.new(recipient_key)
encryptMessage(fileName, 0, choice)