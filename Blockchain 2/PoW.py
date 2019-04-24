import random
import hashlib

"""
Programmed by Kemal Sarper Yücel(syucel - 21031) and Muhammet Cenker Çelik (mcelik - 20418)
"""

def PoW(plen, q, p, g, fname):
    file = open(fname, "r")
    lines = file.readlines()
    m = ""
    for i in range(len(lines)):     # read input
        m += lines[i] + "\n"
    file.close()

    nonce = random.randrange(0, pow(2,128)) # At first, random nonce is selected, then
    # it is incremented until a valid hash is computed
    ptext = m + "\nNonce: " + str(nonce)
    h_obj = hashlib.sha3_256(ptext.encode('UTF-8')).hexdigest()
    while h_obj[0:plen] != "0"*plen:
        nonce += 1
        ptext = m + "\nNonce: " + str(nonce)
        h_obj = hashlib.sha3_256(ptext.encode('UTF-8')).hexdigest()
    return ptext
