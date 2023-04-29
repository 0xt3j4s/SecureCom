# Alice's client code for testing the server

import socket
import hashlib
import hmac
import time
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad



g = 15202575040368582504
n = 136335431983965418811435822457218613337
i_2 = int.from_bytes(get_random_bytes(16), byteorder='big')

keys = {"x01": 0, "x03": 0}


def Diffie_Hellman_key_exchange(g, n, s):
    start_time = time.time()

    g_i = pow(g, i_2, n)


    # Receiving g^i from the server
    exchange = s.recv(1024).decode('utf-8')

    print(f"Received g^j = {exchange}")

    # Sending g^j to the server
    s.send(bytes(str(g_i),'utf-8')) 

    print(f"sending g^i = {g_i}")

    # Generating key by ((g^i)^j) = g^(ij)
    key = pow(int(exchange), i_2, n)
    key = key.to_bytes(16, byteorder='big')

    print("\nDiffie-Hellman key exchange performed successfully on the client side!\n")
    # print("Key i.e. (g^(ij)):", key)

    end_time = time.time()
    
    print("Key Exchange Time (s):", end_time - start_time)

    return key




def authenticate(s, token):
    try:
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
username = "Bob"
id = "x02"
credentials = f"{id}:{username}".encode('utf-8')
hash_object = hashlib.sha256(credentials)
token = hash_object.hexdigest()


def client_client_Key_Exchange(g, n, s):
    start_time = time.time()

    j = int.from_bytes(get_random_bytes(32), byteorder='big')

    g_j = pow(g, j, n)

    # Sending g^i to the server
    s.send(bytes(str(g_j),'utf-8')) 

    print(f"sending g^j = {g_j}")


    # Receiving g^i from the server
    exchange = s.recv(1024).decode('utf-8')

    print(f"Received g^i = {exchange}")

    

    # Generating key by ((g^i)^j) = g^(ij)
    key = pow(int(exchange), j, n)

    key = key.to_bytes(16, byteorder='big')

    
    print("\nDiffie-Hellman key exchange performed successfully on the client side!\n")
    # print("Key i.e. (g^(ij)):", key)

    end_time = time.time()
    
    print("Key Exchange Time (s):", end_time - start_time)

    return key

def sending_mode(key, s):
    while True:
        client = input("Enter username: ")
        s.send(bytes(client,'utf-8'))
        if client == "exit":
            break
        response = s.recv(1024).decode('utf-8')
        if response.startswith("200"):
            client_client_Key_Exchange(g, n, s)
            print("Key exchange successful")
        elif response.startswith("404"):
            print("User not found. Please enter a valid username")


def receiving_mode(key, s):

    response = s.recv(1024).decode('utf-8')

    print(response)

    key_recv = s.recv(1024).decode('utf-8')

    print("key_recv: ", key_recv)

    key_client = pow(int(key_recv), i_2, n)

    key_client = key_client.to_bytes(16, byteorder='big')

    print("Key: ", key_client)



    while True:
        message = s.recv(1024)
        tag = s.recv(1024)
        nonce = s.recv(1024)

        print("Received encrypted text: ", message)
        print("tag: ", tag)
        print("nonce: ", nonce)

        decrypt_cipher = AES.new(key_client, AES.MODE_GCM, nonce=nonce)

        plain_text = decrypt_cipher.decrypt_and_verify(message, tag)

        print('\nReceived message:', plain_text.decode('utf-8'), flush=True)

        # print(message)


def main():

    # Set up socket
    HOST = '0.0.0.0'
    PORT = 810
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

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

            key_s_c2 = Diffie_Hellman_key_exchange(g, n, s)

            print(f"key between server and c2: {key_s_c2}")

            
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


    response = s.recv(1024).decode('utf-8')
    if response:
        print(response)



    receiving_thread = threading.Thread(target=receiving_mode, args=(key_s_c2, s))
    receiving_thread.start()

    send = input("Send/Receive messages? (y/n): ")

    if send == "y":

        sending_thread = threading.Thread(target=sending_mode, args=(key_s_c2, s))
        sending_thread.start()
    


if __name__ == '__main__':
    main()


