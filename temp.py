import socket
import hashlib
import hmac
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# generate g a random integer of 128 bits using get_random_bytes

g = 167088969910373709538603545234966768508
print("g = ", g)
print("len(g) = ", len(str(g)))

from Crypto.Util import number

# generate a 128-bit prime number
p = 172399522729356036106435420801973353319
# prints a random 128-bit prime number


if g < p:
    print("g is less than p")