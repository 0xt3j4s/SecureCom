import socket
import hashlib
import hmac
import time
import os
import threading
from _thread import *
import pandas as pd
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

clients = pd.read_csv("authentication_aes_hmac.csv")

keys = {"x01": None, "x02": None, "x03": None}

client_sockets = {}

g = 15202575040368582504
n = 136335431983965418811435822457218613337
j = int.from_bytes(get_random_bytes(16), byteorder='big')


def Diffie_Hellman_key_exchange(g, n, client_id):

    start_time = time.time()

    g_j = pow(g, j, n)
    
    client = client_sockets[client_id]

    client.send(bytes(str(g_j),'utf-8')) # Sending g^j to client

    print(f"sending g^j = {g_j}", flush=True)

    exchange = client.recv(1024).decode() # Receiving g^i from client

    keys[client_id] = exchange
    print("keys:", keys, flush=True)

    print(f"Received g^i = {exchange}", flush=True)

    # Generating key by ((g^j)^i) = g^(ij)
    key = pow(int(exchange), j, n) 

    key = key.to_bytes(16, byteorder='big')

    print("\nDiffie-Hellman key exchange performed successfully on the server side!\n")
    print("Key i.e. (g^(ij)):", key, flush=True)

    # Perform key agreement with client

    end_time = time.time()
    print("Key Exchange Time (s):", end_time - start_time, flush=True)
    
    return key



def client_auth(client, token):

    tokens = clients.loc[:, 'token'].values

    for i in tokens:
        if i == token:
            client.send(b"200: Authentication successful. You may now send messages to the server.")   
            return True
        
    client.send(b"401: Authentication failed. Closing connection with server...")   
    return False
    

def get_client(token):
    return clients.loc[clients['token'] == token]['id'].values[0]


def get_id_from_username(username):

    users = clients.loc[:,'user_id']

    for i in range(len(users)):
        if users[i] == username:
            return clients.loc[i, 'id']
        
def get_messages(client_id, dest_id):
    client_1 = client_sockets[client_id]
    client_2 = client_sockets[dest_id]

    msg_recv = client_1.recv(1024)
 
    tag_recv = client_1.recv(1024)

    nonce_recv = client_1.recv(1024)

    print("Received ciphertext: ", msg_recv)
    print("tag: ", tag_recv)
    print("nonce: ", nonce_recv)

    alert = "\n200: " + str(client_id) + " has sent you a message."

    client_2.send(bytes(str(alert), encoding='utf-8'))

    time.sleep(0.5)

    key_gen = keys[client_id]

    client_2.send(bytes(str(key_gen), encoding='utf-8'))

    time.sleep(0.5)

    client_2.send(msg_recv)

    time.sleep(0.5)
    
    client_2.send(tag_recv)

    time.sleep(0.5)

    client_2.send(nonce_recv)
    


    

    print(f"Message sent from {client_id} to {dest_id}")


        

def client_server_communication(client_id, address):
    client = client_sockets[client_id]
    resp = ''
    try:
        done = False
        while not done:
            print("Waiting for client to send message...", flush=True)

            recv_name = client.recv(1024).decode('utf-8')
            print("Received recv name: ", recv_name)
            while recv_name != "exit":

                if recv_name == "exit":
                    print("Connection closed by client...", flush=True)
                    done = True
                    break

                if  recv_name in clients.loc[:,'user_id'].values:
                    print("found client")
                    dest = get_id_from_username(recv_name)

                    g_recv = keys[dest]
                    message = "200: " + str(g_recv)
                    client.send(bytes(message, encoding='utf-8'))

                    get_messages(client_id, dest)
                    
                else:
                    print("Invalid client name. Please try again.", flush=True)
                    client.send(b"404: Invalid client name. Please try again.")
                    break

                
                
            
    except OSError as e:
        print(f"OSError: {e}")

    finally:
        client.close()  
    

def handle_client(client, addr):
    try:
        # handle the client's requests
        print("New client connected...", addr)

        token = client.recv(1024).decode('utf-8')
        if client_auth(client, token):
            
            client_id = get_client(token)
            client_sockets[client_id] = client
        
            key_s_c = Diffie_Hellman_key_exchange(g, n, client_id)

            client.send(b"Server: Key exchange successful. You may now send messages to the server.")

            if not token:
                print("Error: Client disconnected...", addr)

            print(f"Key exchange with client {client_id} successful.")
            print("Key: ", key_s_c)

            
            

            communication_thread = threading.Thread(target=client_server_communication, args=(client_id, addr))
            communication_thread.start()
            
        else:
            print("Authentication failed. Closing connection with client...", addr)
             
            
    except ConnectionResetError:
        print("ConnectionResetError: Client closed the connection unexpectedly.")

        # close the client socket
        # client.close()



 


def main():
    # Set up socket
    HOST = '0.0.0.0'  # listen on all available interfaces
    PORT = 810
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen()

    while True:
        client, address = s.accept()

        print(f"\n------Got connection request from {address}------")
        print(f"{address} successfully connected to Server 1...\n")
        

        client_thread = threading.Thread(target=handle_client, args=(client, address))
        client_thread.start()


if __name__ == '__main__':
    main()