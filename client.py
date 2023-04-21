import socket
import hashlib
import hmac
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# Set up socket
HOST = 'localhost'
PORT = 12345
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

# Perform key agreement with server
start_time = time.time()
g =  167088969910373709538603545234966768508
n = 172399522729356036106435420801973353319

j = int.from_bytes(get_random_bytes(16), byteorder='big')

g_j = pow(g, j, n)

# Sending g^j to the server
s.send(bytes(str(g_j),'utf-8')) 

# Receiving g^i from the server
exchange = s.recv(1024).decode('utf-8')

# Generating key by ((g^i)^j) = g^(ij)
key = pow(int(exchange), j, n)
print("\nDiffie-Hellman key exchange performed successfully on the client side!\n")
print("Key i.e. (g^(ij)):", key)

end_time = time.time()

print("Key Exchange Time (s):", end_time - start_time)

# Generate AES key from shared key
aes_key = hashlib.sha256(str(key).encode()).digest()[:16]
print("\nAES Key:", aes_key)

# Derive HMAC key from shared key
hmac_key = hashlib.sha256(b"HMAC_" + str(key).encode()).digest()[:16]
print("\nHMAC Key:", hmac_key)

# Encrypt message and calculate HMAC
message = 'Hello, world!'
cipher = AES.new(aes_key, AES.MODE_EAX)
start_time = time.time()
cipher_text, tag = cipher.encrypt_and_digest(pad(message.encode(), AES.block_size))
end_time = time.time()
print('\nMessage:', message)
print("\nMessage Encryption Time (s):", end_time - start_time)

# Send encrypted message and HMAC to server
start_time = time.time()
s.sendall(cipher.nonce + cipher_text)
h = hmac.new(hmac_key, digestmod=hashlib.sha256)
h.update(cipher.nonce + cipher_text)
mac = h.digest()
s.sendall(mac)
end_time = time.time()
print("\nHMAC Time (s):", end_time - start_time)

# Close connection
s.close()
