import oracle

def attack(ciphertext):
	guessedClear = b''
	splitString = lambda x, n: [x[i:i+n] for i in range(0, len(x), n)]
	blocks = splitString(ciphertext, oracle.blockSize)
	for block_n in range(len( blocks ) - 1, 0, -1):
		splicedCiphertext = blocks[block_n - 1] + blocks[block_n]
		decodedBytes = b'?' * oracle.blockSize
		for byte in range(oracle.blockSize - 1, -1, -1):
			newPadLen = oracle.blockSize - byte
			hackedCiphertextTail = b''
			for padderIndex in range(1, newPadLen):
				hackedCiphertextTail += bytearray.fromhex('{:02x}'.format(newPadLen ^ decodedBytes[byte + padderIndex]))
			for i in range(0, 256):
				attackStr = bytearray.fromhex('{:02x}'.format((i ^ splicedCiphertext[byte])))
				hackedCiphertext = splicedCiphertext[:byte] + attackStr + hackedCiphertextTail + splicedCiphertext[byte + 1 + newPadLen - 1:]
				if(oracle.paddingCheck( hackedCiphertext)):
					testCorrectness = hackedCiphertext[:byte - 1] + bytearray.fromhex( '{:02x}'.format(( 1 ^  hackedCiphertext[byte]))) + hackedCiphertext[byte:]
					if(not oracle.paddingCheck(testCorrectness)):
						continue
					decodedBytes = decodedBytes[:byte] + bytearray.fromhex('{:02x}'.format( hackedCiphertext[byte] ^ newPadLen)) + decodedBytes[byte + 1:]
					guessedClear = bytearray.fromhex('{:02x}'.format( i ^ newPadLen)) + guessedClear
					break
	return guessedClear[:-guessedClear[-1]]

def testTheAttack():
    messages = (b'Hello INSE6120', 
				b'This is a padding oracle attack test can be applied to the CBC mode of operation,' +
				b'attackers to decrypt messages through the oracle using the oracle key, without knowing the encryption key'
				)
    for msg in messages:
        print('Testing:', msg, 'OF LENGTH', len(msg))
        crackedCt = attack(oracle.encrypt(msg))
        assert(crackedCt == msg)

if __name__ == '__main__':
    testTheAttack()