import hashlib
import random

"""
Programmed by Kemal Sarper Yücel(syucel - 21031) and Muhammet Cenker Çelik (mcelik - 20418)
"""

def AddBlock2Chain(plen, prev, new):
    phash = b'0'
    if prev != 0:
        phash = hashlib.sha3_256(prev.encode('UTF-8')).hexdigest()
    new += "Previous Hash: " + str(phash)
    nonce = random.randrange(0, pow(2, 128))  # At first, random nonce is selected, then
    # it is incremented until a valid hash is computed
    ptext = new + "\nNonce: " + str(nonce)
    h_obj = hashlib.sha3_256(ptext.encode('UTF-8')).hexdigest()
    while h_obj[0:plen] != "0" * plen:
        nonce += 1
        ptext = new + "\nNonce: " + str(nonce)
        h_obj = hashlib.sha3_256(ptext.encode('UTF-8')).hexdigest()
    return ptext