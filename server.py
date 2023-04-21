import socket
import hashlib
import hmac
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# Set up socket
HOST = ''  # listen on all available interfaces
PORT = 12345
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)

# Wait for client to connect
conn, addr = s.accept()
print('Connected by', addr)

start_time = time.time()
g =  167088969910373709538603545234966768508
n = 172399522729356036106435420801973353319
i = int.from_bytes(get_random_bytes(16), byteorder='big')
print("i = ", i)
g_i = pow(g, i, n)
print("g_i = ", g_i)


conn.send(bytes(str(g_i),'utf-8')) # Sending g^i to client
print(f"\nSending g^i to client: {g_i}")

exchange = int(conn.recv(1024).decode()) # Receiving g^j from client
print(f"Receiving g^j from client: {exchange}")
# Generating key by ((g^j)^i) = g^(ij)
key = pow(int(exchange), i, n) 

print("\nDiffie-Hellman key exchange performed successfully on the server side!")
print("Key i.e. (g^(ij)):", key)

# Perform key agreement with client

end_time = time.time()
print("Key Agreement Time (s):", end_time - start_time)

# Generate AES key from shared secret
aes_key = hashlib.sha256(str(key).encode()).digest()[:16]
print("AES Key:", aes_key)


# Derive HMAC key from shared secret
hmac_key = hashlib.sha256(b"HMAC_" + str(key).encode()).digest()[:16]
print("HMAC Key:", hmac_key)

# Receive encrypted message and HMAC from client
start_time = time.time()
cipher_text = conn.recv(1024)
print("Received Cipher Text:", cipher_text)
mac = conn.recv(1024)
print("Received HMAC:", mac)

# Verify HMAC
h = hmac.new(hmac_key, digestmod=hashlib.sha256)
h.update(cipher_text)
calculated_mac = h.digest()
print("Calculated HMAC:", calculated_mac)
if calculated_mac == mac:
    # Decrypt message
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=cipher_text[:16])
    plain_text = unpad(cipher.decrypt(cipher_text[16:]), AES.block_size)
    print('Received message:', plain_text.decode())
else:
    print('HMAC verification failed')
end_time = time.time()
print("Message Decryption Time (s):", end_time - start_time)

# Close connection
conn.close()
