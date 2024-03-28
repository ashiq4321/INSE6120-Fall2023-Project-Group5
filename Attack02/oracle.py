from Crypto.Cipher import AES
from Crypto import Random

keyLength = 16
blockSize = AES.block_size

randomGen = Random.new()
key = randomGen.read(keyLength)

def addPadding(msg):
	padLen = blockSize - (len(msg) % blockSize)
	padding = bytes([padLen]) * padLen
	return msg + padding

def removePadding(data):
	padLen = data[-1]
	if padLen < 1 or padLen > blockSize:
		return None
	for i in range(1, padLen):
		if data[-i-1] != padLen:
			return None
	return data[:-padLen]

def encrypt(msg):
	iv = randomGen.read(AES.block_size)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return iv + cipher.encrypt(addPadding(msg))

def decrypt(data):
	iv = data[:blockSize]
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return removePadding(cipher.decrypt(data[blockSize:]))

def paddingCheck(data):
	return decrypt(data) is not None