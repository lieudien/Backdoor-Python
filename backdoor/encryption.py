from Cryto.Cipher import AES
from Cryto import Random
import base64

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
            chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def encrypt(data, password):
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(password, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(data))

def decrypt(data, password):
    if len(data) <= 16:
        return ""
    data = base64.b64decode(data)
    iv = data[:16]
    cipher = AES.new(password, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[16:]))
