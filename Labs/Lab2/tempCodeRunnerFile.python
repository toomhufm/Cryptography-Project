from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# khóa mã hóa và thông điệp được mã hóa
key = b'0123456789ABCDEF'
iv = b'fedcba9876543210'
message = b'This is a secret message.'

# tạo đối tượng AES và mã hóa thông điệp
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(message, AES.block_size))

# thay đổi một số bit trong khối đầu tiên của ciphertext
ciphertext = bytearray(ciphertext)
ciphertext[0] ^= 1

# giải mã ciphertext
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(bytes(ciphertext)), AES.block_size)

print(plaintext)