import random
import DS       # This is the file from Phase I

"""
Programmed by Kemal Sarper Yücel(syucel - 21031) and Muhammet Cenker Çelik (mcelik - 20418)
"""


def gen_random_tx(q, p, g):
    # Generate Serial
    serial = random.randrange(pow(2, 127), pow(2, 128))
    a1, pk1 = DS.KeyGen(q, p, g)
    a2, pk2 = DS.KeyGen(q, p, g)    # This isn't actually the key of the payee, the payer would know the wallet id in a real transaction
    amount = random.randrange(1, 1000001)
    s, h = DS.SignGen(amount, q, p, g, a1)
    trans = "**** Bitcoin transaction ****\n" + "Serial number: " + str(serial) + "\nPayer public key (beta): " + \
            str(pk1) + "\nPayee public key (beta): " + str(pk2) + "\nAmount: " + str(amount) + "\nSignature (s): " + \
            str(s) + "\nSignature (h): " + str(h) + "\n"
    return trans
