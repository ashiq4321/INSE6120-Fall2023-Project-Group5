import random
import sympy

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception("No modular inverse")
    return x % m

def generatePrime(bitLength):
    while True:
        lb = 2 ** (bitLength - 1)
        ub = (2 ** bitLength) - 1
        candidate = random.randint(lb, ub)
        if sympy.isprime(candidate):
            return candidate

def bytesToInteger(bytesObj):
    return int.from_bytes(bytesObj, byteorder="big")

def integerToBytes(integer):
    k = integer.bit_length()
    bytesLength = k // 8 + (k % 8 > 0)
    bytesObj = integer.to_bytes(bytesLength, byteorder="big")
    return bytesObj