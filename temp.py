import socket
import hashlib
import hmac
import time
import pandas as pd
import sys
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime
import secrets

# salt = secrets.token_bytes(16)

username = "Bob"
# id = "x02"
password = "bob!@357"
credentials = f"{username}:{password}".encode('utf-8')
hash_object = hashlib.sha256(credentials)
token = hash_object.hexdigest()

print("token: ", token)

clients = pd.read_csv("authentication_aes_hmac.csv")

all_tokens = clients.loc[:,'token'].values

for i in all_tokens:
    if i == token:
        # client.send(b"200: A
        # 
        # uthentication successful. You may now send messages to the server.")  
        print(True)
        break
    
print(False)



from Crypto.Util.number import getPrime
from Crypto.Random import get_random_bytes

p = getPrime(64)
q = getPrime(64)

N = p*q
g = 2
while g == 2 or g == 1:
    g = int.from_bytes(get_random_bytes(16), byteorder='big')%N

print("N: ", N)
print("g: ", g)

n = "50688311207100724012131965227052314128101131318328922619944512369187572507371"
print(len(n))
