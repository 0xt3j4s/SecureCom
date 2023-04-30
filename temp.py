import socket
import hashlib
import hmac
import time
import pandas as pd
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


j = int.from_bytes(get_random_bytes(16), byteorder='big')
N = int.from_bytes(get_random_bytes(16), byteorder='big')

print(j)
print(N)

token = "e8741bebbf7c9d206d7bcb24e284b51d4d08fb1560f7ecd9fa4968edfa23c37f"
clients = pd.read_csv("authentication_aes_hmac.csv")

# access pandas dataframe to get the id of the token
print(clients.loc[clients['token'] == token]['id'].values[0])


# for i in range(len(clients)):
#     if clients[i][0] == token:
#         print("Found client")


# Given the token find if it is present in the list of tokens
# If yes, return the id of the client
# If no, return -1
# print(type(clients.loc[:,"token"]))
# print(type(clients.loc[:,"token"].values))

# def client_auth(client, token):

#     tokens = clients.loc[:, 'token'].values
    

#     for i in tokens:
#         print(i)
#         if i == token:
#             # client.send(b"200: Authentication successful. You may now send messages to the server.")   
#             return True
       
#     return False
        
# print(client_auth(None, token))

from Crypto.Util.number import getPrime

# Generate a 2048-bit prime number for N
p = getPrime(64)
q = getPrime(64)

N = p*q


# Generate a random integer between 2 and N-2 for G
G = 2
while G == 2 or G == 1:
    G = int.from_bytes(get_random_bytes(8), byteorder='big') % N


print("G:", G)
print("N:", N)

# def get_id_from_username(username):

#     users = clients.loc[:,'user_id']

#     for i in range(len(users)):
#         if users[i] == username:
#             return clients.loc[i, 'id']

            

# print(get_id_from_username("Jack"))

# if "Jack" in clients.loc[:,'user_id'].values:
#     print("bro")

# creating a new dictionary
my_dict ={"Java":100, "Python":112, "C":11}
 
# one-liner
print("One line Code Key value: ", list(my_dict.keys())[list(my_dict.values()).index(100)])

final_text = ""
done = False


    
# while True:  

#     message = input("Enter message [Enter 'exit' or '0 to leave the chat]: ")

#     print("message: ", message)      
    
#     final_text += message
#     final_text += "\n"

#     if message == "exit" or message == '0':

#         break

# print(final_text)

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# data = b'secret data'

# # key = get_random_bytes(16)

# # print(key)

# Key =  b'_>\xdfl\x07\xe7\x06\xf8\x1b$ ZP\xbd\x08\xdd'
# # tag = b'*\xff6YH\nn\xaa\x94\xb0\x03\xf5pK{K'
# # data = b"Hi Bob\nAlice here\nPlease listen"
# ciphertext = b'T`\xe6\xc9\xeaksqd\x95\x9cu\xb2\x18r\xb3\x0ep\xca\xd6\x9b\xb9^A\x83\t\x85\x8eC\xb2\x00'

# cipher = AES.new(Key, AES.MODE_CCM)
# # ciphertext = cipher.encrypt(data)



# ciphertext, tag = cipher.encrypt_and_digest(data)
# # ct_bytes = cipher.encrypt(pad(data, AES.block_size))
# # ciphertext = cipher.encrypt(data)

# decrypt_cipher = AES.new(Key, AES.MODE_CCM)

# data = decrypt_cipher.decrypt(ciphertext)

# print(data)

# # ciphertext = b'#Yd1Dj\x91yoB\xcc_\xf3\x15\x80G\xc4\x96:\xddc\xc2LZ\xfb\x83\xbcB\x94\x0c\x9bB'

# # nonce =  b'\xed\xe2\xb9\x83L\xe5\x8e{\t\xcf\xbd\xf5\xae\xf3\xf5\xb5'


# print(ciphertext)
# print(tag)

# # nonce = cipher.nonce

# cipher = AES.new(Key, AES.MODE_EAX, nonce = None)


# data = cipher.decrypt(ciphertext)

# print("data: ", data.decode('utf-8'))




# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes

# # Shared secret between the clients
# shared_secret = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'

# # Generate a random nonce
# # nonce = get_random_bytes(16)

# # Initialize the cipher in GCM mode with the shared secret and nonce
# # cipher = AES.new(shared_secret, AES.MODE_GCM, nonce=nonce)

# # Encrypt the plaintext
# # plaintext = b"Hello, world!"



# ciphertext = b'z\xda\xc8\xeeQ\xbc0Q\xb3\x0e[IB'
# tag = b'\xa6\xe0e\x7f\xc2\xbd\xb1\xb1\xbdb\xac0\xf0<\x93\x97'
# nonce = b'\x18gv\xa1t\xf1\xed\x83)\x10C;\xb4\x02\x90\xd7'
# # tag = b'\nL\xac\xec,\xf1\x19\x1a=\xefhB\x86\xac&\x8a'
# # nonce = b'\xc2\xd3_%\xff\x8b\xfc/h\xc2\xff\x11'
# # tag = b'\xcaq\x01Vj\xedz\xf6\xef\xe5T\x06"\xf7$\xaf'
# # ciphertext, tag = cipher.encrypt_and_digest(plaintext)

# # print(ciphertext)
# # print(tag)

# # print(nonce)

# # Send the ciphertext, nonce, and tag to the receiver

# # # # Initialize the cipher in GCM mode with the shared secret and received nonce
# cipher = AES.new(shared_secret, AES.MODE_GCM, nonce=nonce)

# # # # # Decrypt the ciphertext
# plaintext = cipher.decrypt_and_verify(ciphertext, tag)

# print(plaintext.decode('utf-8'))


