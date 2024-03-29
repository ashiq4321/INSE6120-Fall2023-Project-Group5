import utils

def generateKey(modulusLength):
    primeLength = modulusLength // 2
    e = 3
    p = 4
    while (p - 1) % e == 0:
        p = utils.generatePrime(primeLength)
    q = p
    while q == p or (q - 1) % e == 0:
        q = utils.generatePrime(primeLength)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = utils.modinv(e, phi)
    publicKey = (n, e)
    secretKey = (n, d)
    return publicKey, secretKey

def encryptInteger(publicKey, m):
    (n, e) = publicKey
    if m > n:
        raise ValueError("Message is to big for current RSA scheme!")
    return pow(m, e, n)

def decryptInteger(secretKey, c):
    (n, d) = secretKey
    return pow(c, d, n)

def encryptString(publicKey, message):
    integer = utils.bytesToInteger(message)
    encInteger = encryptInteger(publicKey, integer)
    encString = utils.integerToBytes(encInteger)
    return encString

def decryptString(secretKey, ciphertext):
    encInteger = utils.bytesToInteger(ciphertext)
    integer = decryptInteger(secretKey, encInteger)
    message = utils.integerToBytes(integer)
    return message
