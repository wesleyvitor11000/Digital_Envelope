from asyncio.windows_events import NULL
from Crypto.Cipher import AES, DES, ARC4
from tkinter import Tk
from tkinter.filedialog import askopenfilename
from Crypto.Random import get_random_bytes

def encryptMessage(fileName, receiverKey, algorithm):
    file = open(fileName, "r")
    content = file.read()
    key = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_EAX)

    '''match algorithm:
        case 1:
            cipher = AES.new(receiverKey, AES.MODE_OFB)
            print("type  " + type(cipher))
        case 2:
            cipher = DES.new(receiverKey, DES.MODE_OFB)
        case 3:
            cipher = ARC4.new(receiverKey, ARC4.MODE_OFB)
'''
    #encrypted = cipher.iv + cipher.encrypt(content)
    encrypted, tag = cipher.encrypt_and_digest(content)
    print(encrypted)

print('select file to encrypt:')
Tk().withdraw()
fileName = askopenfilename()
print('choose the algorithm:\n1 - AES \n2 - DES \n3 - RC4')
choice = input()

encryptMessage(fileName, 0, choice)