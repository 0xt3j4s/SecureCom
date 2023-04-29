# Bob's client

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
i_1 = int.from_bytes(get_random_bytes(16), byteorder='big')


keys = {"x02": 0, "x03": 0}


# def box_text(text, width):
#     box_chars = {
#         "horizontal": "─",
#         "vertical": "│",
#         "top_left": "┌",
#         "top_right": "┐",
#         "bottom_left": "└",
#         "bottom_right": "┘",
#     }
#     box_width = width - 2  # account for left and right borders
#     horizontal_border = box_chars["horizontal"] * box_width
#     lines = text.split("\n")
#     max_line_length = max(len(line) for line in lines)
#     horizontal_padding = (box_width - max_line_length) // 2
#     padding = " " * horizontal_padding
#     padded_lines = [f"{padding}{line}{padding}" for line in lines]
#     if len(lines) == 1:
#         box_height = 1
#     else:
#         box_height = len(lines) + 1  # account for top and bottom borders
#     vertical_border = "\n".join(
#         f"{box_chars['vertical']}{' ' * (box_width)}{box_chars['vertical']}"
#         for _ in range(box_height - 2)
#     )
#     top_border = f"{box_chars['top_left']}{horizontal_border}{box_chars['top_right']}"
#     bottom_border = f"{box_chars['bottom_left']}{horizontal_border}{box_chars['bottom_right']}"
#     return f"{top_border}\n{vertical_border}\n{padded_lines[0]}\n{vertical_border}\n{''.join(padded_lines[1:])}\n{vertical_border}\n{bottom_border}"





def Diffie_Hellman_key_exchange(g, n, s):
    start_time = time.time()


    g_i = pow(g, i_1, n)


    # Receiving g^j from the server
    exchange = s.recv(1024).decode('utf-8')

    print(f"Received g^j = {exchange}")

    # Sending g^j to the server
    s.send(bytes(str(g_i),'utf-8')) 

    print(f"sending g^i = {g_i}")

    # Generating key by ((g^i)^j) = g^(ij)
    key = pow(int(exchange), i_1, n)

    key = key.to_bytes(16, byteorder='big')
    
    print("\nDiffie-Hellman key exchange performed successfully on the client side!\n")
    print("Key i.e. (g^(ij)):", key)

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
        # s.close()
        # exit()

# Perform key agreement with server
username = "Alice"
id = "x01"
credentials = f"{id}:{username}".encode('utf-8')
hash_object = hashlib.sha256(credentials)
token = hash_object.hexdigest()


def client_client_Key_Exchange(response):

    # response2 = s.recv(1024).decode('utf-8')
    g_recv = int(response[5:])


    start_time = time.time()

    key = pow(g_recv, i_1, n) # shared secret key
    key = key.to_bytes(16, byteorder='big')

    end_time = time.time()
    
    print("Key Exchange Time (s):", end_time - start_time)

    return key


def AES_encrypt(plaintext, key):
    # Generate AES key from shared key

    start_time = time.time()

    nonce = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_GCM, nonce = nonce)
    cipher_text, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))


    end_time = time.time()

    print('\nMessage:', plaintext)
    print("\nMessage Encryption Time (s):", end_time - start_time)

    return [cipher_text, tag, nonce]

def send_messages(s, dest, key, key_c1_c2):

    final_text = ""
    while True:  

        message = input("Enter message [Enter 'exit' or '0 to leave the chat]: ")

        if message == "exit" or message == '0':
            break


        print("message: ", message)      
        
        final_text += message
        final_text += "\n"


    print("final_text: ", final_text)
    
    encryption = AES_encrypt(final_text, key_c1_c2)

    final_text = encryption[0]
    tag = encryption[1]
    nonce = encryption[2]

    

    print("Sending the final encrypted text: ", final_text)
    print("tag: ", tag)
    print("nonce: ", nonce)

    s.send(final_text)
    time.sleep(0.1)
    s.send(tag)
    time.sleep(0.1)
    s.send(nonce)


def sending_mode(key, s):
    while True:
        recv = input("Enter username: ")
        s.send(bytes(recv,'utf-8'))
        if recv == "exit":
            break
        
        response = s.recv(1024).decode('utf-8')
        print("Response:", response)
        if response.startswith("200"):
            key_c1_c2 = client_client_Key_Exchange(response)
            print("Key exchange successful")
            print("Key: ", key_c1_c2)
            send_messages(s, recv, key, key_c1_c2)
        elif response.startswith("404"):
            print("User not found. Please enter a valid username")


def receiving_mode(key, s):

    while True:
        message = s.recv(1024).decode('utf-8')


def main():

    # Set up socket
    HOST = '0.0.0.0'
    PORT = 810
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect to server
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

            key_s_c1 = Diffie_Hellman_key_exchange(g, n, s)

            print(f"key between server and c1: {key_s_c1}")

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

    receiving_thread = threading.Thread(target=receiving_mode, args=(key_s_c1, s))
    receiving_thread.start()

    send = input("Send/Receive messages? (y/n): ")

    if send == "y":
        # Take input from user and send to server
        
        sending_thread = threading.Thread(target=sending_mode, args=(key_s_c1, s))
        
        sending_thread.start()

if __name__ == '__main__':
    main()




