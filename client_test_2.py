# Alice's client code for testing the server

import socket
import hashlib
import hmac
import time
import sys
import select
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


def AES_encrypt(plaintext, key):

    start_time = time.time()

    nonce = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_GCM, nonce = nonce)
    cipher_text, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))


    end_time = time.time()

    print('\nMessage:', plaintext)
    print("\nMessage Encryption Time (s):", end_time - start_time)

    return [cipher_text, tag, nonce] # returning ciphertext, tag and nonce



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


def client_client_Key_Exchange(response):

    g_recv = int(response[5:])
    print("g_recv: ", g_recv)

    start_time = time.time()

    key = pow(g_recv, i_2, n) # shared secret key
    key = key.to_bytes(16, byteorder='big')

    end_time = time.time()
    
    print("Key Exchange Time (s):", end_time - start_time)

    return key

def send_messages(s, dest, key, key_c2_c):

    final_text = ""
    while True:  

        message = input("Enter message [Enter 'exit' or '0 to leave the chat]: ")

        if message == "exit" or message == '0':
            break


        # print("message: ", message)      
        
        final_text += message
        final_text += "\n"


    # print("final_text: ", final_text)
    
    encryption = AES_encrypt(final_text, key_c2_c)

    final_text = encryption[0]
    tag = encryption[1]
    nonce = encryption[2]

    # print("Sending the final encrypted text: ", final_text)
    # print("tag: ", tag)
    # print("nonce: ", nonce)

    s.send(final_text)
    time.sleep(0.1)
    s.send(tag)
    time.sleep(0.1)
    s.send(nonce)

    print(f"Message sent to {dest} successfully")

def sending_mode(key, s):
    while True:
        recv_client = input("Enter username [Enter 'exit' or '0 to leave the chat]: ")
        s.send(bytes(recv_client,'utf-8'))
        if recv_client == "exit":
            break
        response = s.recv(1024).decode('utf-8')
        if response.startswith("200"):
            key_c2_c = client_client_Key_Exchange(response)
            print("Key exchange successful")
            print("Key: ", key_c2_c)

            send_messages(s, recv_client, key, key_c2_c)
        elif response.startswith("404"):
            print("User not found. Please enter a valid username")

    print("In receiving mode...")


def receiving_mode(key, s):

    response = s.recv(1024).decode('utf-8')

    # print(response)

    key_recv = s.recv(1024).decode('utf-8')

    print("key_recv: ", key_recv)

    key_client = pow(int(key_recv), i_2, n)

    key_client = key_client.to_bytes(16, byteorder='big')

    print("Key: ", key_client)

    while True:
        message = s.recv(1024)
        tag = s.recv(1024)
        nonce = s.recv(1024)

        # print("Received encrypted text: ", message)
        # print("tag: ", tag)
        # print("nonce: ", nonce)

        decrypt_cipher = AES.new(key_client, AES.MODE_GCM, nonce=nonce)

        plain_text = decrypt_cipher.decrypt_and_verify(message, tag)

        print('\nReceived message:', plain_text.decode('utf-8'), flush=True)



def main():

    # Set up socket
    HOST = '0.0.0.0'
    PORT = int(input("Enter port number:"))
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

    print("\n Receiving thread started...\n")
    print("\nClient is now in receiving mode...\n")


    # Prompt the user to send messages
    sys.stdout.write("Send messages? (y/n): ")
    sys.stdout.flush()

    # Wait for 5 seconds for a response
    readable, _, _ = select.select([sys.stdin], [], [], 5)

    # Check if there is a response
    if readable:
        response = sys.stdin.readline().strip()
        if response.lower() == 'y':
            sending_thread = threading.Thread(target=sending_mode, args=(key_s_c2, s))
        
            sending_thread.start()

            print("Starting sending thread...\n")
            print("You can now send messages to other clients...\n")
        else:
            print("Ok, Client in Receiving mode...")
    else:
        print("No response, Client in Receiving mode...")
    


if __name__ == '__main__':
    main()


