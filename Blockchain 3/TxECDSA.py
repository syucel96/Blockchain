import random
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
from ecpy.formatters import decode_sig, encode_sig

"""
Programmed by Kemal Sarper Yücel(syucel - 21031) and Muhammet Cenker Çelik (mcelik - 20418)
"""


def gen_random_tx(curve):
    serial = random.randrange(pow(2, 127), pow(2, 128))
    amount = random.randrange(1, 1000001)

    n = curve.order
    P = curve.generator

    sA = random.randint(0, n)
    sB = random.randint(0, n)

    skA = ECPrivateKey(sA, curve)
    skB = ECPrivateKey(sB, curve)
    QA = sA * P
    QB = sB * P

    pkA = ECPublicKey(QA)
    pkB = ECPublicKey(QB)

    signer = ECDSA()

    trans = "**** Bitcoin transaction ****" + \
        "\nSerial number: " + str(serial) + \
        "\nPayer public key - x: " + str(QA.x) + \
        "\nPayer public key - y: " + str(QA.y) + \
        "\nPayee public key - x: " + str(QB.x) + \
        "\nPayee public key - y: " + str(QB.y) + \
        "\nAmount: " + str(amount) + "\n"
    t = trans.encode("UTF-8")
    sig = signer.sign(t, skA)

    (r, s) = decode_sig(sig)

    trans += "Signature (r): " + str(r) + "\n" + "Signature (s): " + str(s) + "\n"

    return trans
