import rsa
import utils
import os
import random
import time
from collections import namedtuple

Interval = namedtuple("Interval", ["lower_bound", "upper_bound"])

modulusSize = 256
pk, sk = rsa.generateKey(modulusSize)
(n, e) = pk
k = modulusSize // 8
t_start = time.perf_counter()
global queries
queries = 0

def floor(a, b):
    return a // b

def ceil(a, b):
    return a // b + (a % b > 0)

def PKCS1Encode(message, totalBytes):
    if len(message) > totalBytes - 11:
        raise Exception("Message to big for encoding scheme!")
    pad_len = totalBytes - 3 - len(message)
    padding = bytes(random.sample(range(1, 256), pad_len))
    encoded = b"\x00\x02" + padding + b"\x00" + message
    return encoded

def PKCS1Decode(encoded):
    encoded = encoded[2:]
    idx = encoded.index(b"\x00")
    message = encoded[idx + 1 :]
    return message

def oracle(ciphertext):
    global queries
    queries += 1
    t = time.perf_counter()
    if queries % 500 == 0:
        print("Query #{} ({} s)".format(queries, round(t - t_start, 3)))
    encoded = rsa.decryptString(sk, ciphertext)
    if len(encoded) > k:
        raise Exception("Invalid PKCS1 encoding after decryption!")
    if len(encoded) < k:
        zeroPad = b"\x00" * (k - len(encoded))
        encoded = zeroPad + encoded
    return encoded[0:2] == b"\x00\x02"

def prepare(message):
    messageEncoded = PKCS1Encode(message, k)
    ciphertext = rsa.encryptString(pk, messageEncoded)
    return ciphertext

def findSmallestS(lower_bound, c):
    s = lower_bound
    while True:
        attempt = (c * pow(s, e, n)) % n
        attempt = utils.integerToBytes(attempt)
        if oracle(attempt):
            return s
        s += 1

def findSInRange(a, b, prev_s, B, c):
    ri = ceil(2 * (b * prev_s - 2 * B), n)
    while True:
        siLower = ceil(2 * B + ri * n, b)
        siUpper = ceil(3 * B + ri * n, a)
        for si in range(siLower, siUpper):
            attempt = (c * pow(si, e, n)) % n
            attempt = utils.integerToBytes(attempt)
            if oracle(attempt):
                return si
        ri += 1

def safeIntervalInsert(M_new, interval):
    for i, (a, b) in enumerate(M_new):
        if (b >= interval.lower_bound) and (a <= interval.upper_bound):
            lb = min(a, interval.lower_bound)
            ub = max(b, interval.upper_bound)
            M_new[i] = Interval(lb, ub)
            return M_new
    M_new.append(interval)
    return M_new

def updateIntervals(M, s, B):
    M_new = []
    for a, b in M:
        rLower = ceil(a * s - 3 * B + 1, n)
        rUpper = ceil(b * s - 2 * B, n)
        for r in range(rLower, rUpper):
            lower_bound = max(a, ceil(2 * B + r * n, s))
            upper_bound = min(b, floor(3 * B - 1 + r * n, s))
            interval = Interval(lower_bound, upper_bound)
            M_new = safeIntervalInsert(M_new, interval)
    M.clear()
    return M_new

def bleichenbacher(ciphertext):
    c = utils.bytesToInteger(ciphertext)
    B = 2 ** (8 * (k - 2))
    M = [Interval(2 * B, 3 * B - 1)]
    s = findSmallestS(ceil(n, 3 * B), c)
    M = updateIntervals(M, s, B)

    while True:
        if len(M) >= 2:
            s = findSmallestS(s + 1, c)
        elif len(M) == 1:
            a, b = M[0]
            if a == b:
                return utils.integerToBytes(a % n)
            s = findSInRange(a, b, s, B, c)
        M = updateIntervals(M, s, B)

def main():
    global queries
    simulations = False
    if simulations:
        total = []
        for i in range(100):
            message = bytes(os.urandom(11))
            ciphertext = prepare(message)
            decrypted = bleichenbacher(ciphertext)
            decrypted = PKCS1Decode(decrypted)
            assert decrypted == message
            total.append(queries)
            print(i)
            queries = 0
        print(total)
    else:
        message = b"Hi. It's 6120 Project"
        ciphertext = prepare(message)
        decrypted = bleichenbacher(ciphertext)
        decrypted = PKCS1Decode(decrypted)
        assert decrypted == message
        print("----------")
        print("queries:\t{}".format(queries))
        print("message:\t{}".format(message))
        print("decrypt:\t{}".format(decrypted))

def run_tests(m):
    menc = PKCS1Encode(m, k)
    print("1. (un)pad:", PKCS1Decode(menc) == m)
    m1 = rsa.decryptString(sk, rsa.encryptString(pk, m))
    print("2. rsa w/o pad:", m == m1)
    m2 = PKCS1Decode(rsa.decryptString(sk, rsa.encryptString(pk, menc)))
    print("3. rsa w/ pad:", m == m2)
    m3 = oracle(rsa.encryptString(pk, menc)) == True
    print("4. oracle well-formed:", m3)
    m4 = oracle(rsa.encryptString(pk, m)) == False
    print("5. oracle not well-formed", m4)

if __name__ == "__main__":
    main()
