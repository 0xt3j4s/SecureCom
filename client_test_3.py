# Eve

import socket
import hashlib
import hmac
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


g = 15202575040368582504
n = 136335431983965418811435822457218613337

i_3 = int.from_bytes(get_random_bytes(8), byteorder='big')

keys = {"x01": 0, "x02": 0}

def Diffie_Hellman_key_exchange(g, n, s):
    start_time = time.time()

    i_3 = int.from_bytes(get_random_bytes(16), byteorder='big')

    g_i = pow(g, i_3, n)


    # Receiving g^i from the server
    exchange = s.recv(1024).decode('utf-8')

    print(f"Received g^j = {exchange}")

    # Sending g^j to the server
    s.send(bytes(str(g_i),'utf-8')) 

    print(f"sending g^i = {g_i}")

    # Generating key by ((g^i)^j) = g^(ij)
    key = pow(int(exchange), i_3, n)
    print("\nDiffie-Hellman key exchange performed successfully on the client side!\n")
    print("Key i.e. (g^(ij)):", key)

    end_time = time.time()
    
    print("Key Exchange Time (s):", end_time - start_time)

    return key

# Set up socket
HOST = '0.0.0.0'
PORT = 811
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def authenticate(s, token):
    try:
        s.send(bytes(str(username),'utf-8'))
        time.sleep(0.1)
        s.send(bytes(str(token),'utf-8'))
        response = s.recv(1024).decode('utf-8').strip()
        if response.startswith("200"):
            return True
        elif response.startswith("401"):
            return False
    except BrokenPipeError:
        print("Connection reset by server")
        s.close()
        exit()

# Perform key agreement with server
username = "Jack"
# id = "x03"
password = "^jack*notjack"
credentials = f"{username}:{password}".encode('utf-8')
hash_object = hashlib.sha256(credentials)
token = hash_object.hexdigest()


connected = False

while not connected:
    try:
        s.connect((HOST, PORT))
        connected = True
        print("Connection established with server")
    except ConnectionRefusedError:
        print("Could not connect to server. Retrying in 5 seconds...")
        time.sleep(5)



try:   
    if authenticate(s, token):
        print("Authentication successful")
        g =  167088969910373709538603545234966768509
        n = 172399522729356036106435420801973353319

        key_s_c3 = Diffie_Hellman_key_exchange(g, n, s)
        # key_c1_c2 = Diffie_Hellman_key_exchange(g, n, s)


        # print(f"key between c1 and c2: {key_c1_c2}")
        print(f"key between server and c3: {key_s_c3}")


        # send message to client 2
        # client_2 = input("Enter the username of the client you can communicate with: ")


        # # send client name to server

        # s.send(bytes(client_2,'utf-8'))
        
    else:
        print("Authentication failed")
        

except (ConnectionResetError, BrokenPipeError):
    print("Connection closed by server. Reconnecting...")
    connected = False
    while not connected:
        try:
            s.connect((HOST, PORT))
            connected = True
            print("Connection established with server")
        except ConnectionRefusedError:
            print("Connection refused by server")

    
while True:
    # keep connection alive
    # start key exchange with client 2 through server using Diffie Hellman Key exchange

    


    # receive message from client 2



    pass




