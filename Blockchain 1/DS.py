 # !pip install pycryptodome
"""
Programmed by syucel and mcelik
"""
import random
from Crypto.Hash import SHA3_256


def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y


# Function to take multiplicative inverse
def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m


def is_Prime(n):    # Taken from https://rosettacode.org/wiki/Miller%E2%80%93Rabin_primality_test
    """
    Miller-Rabin primality test.

    A return value of False means n is certainly not prime. A return value of
    True means n is very likely a prime.
    """
    if n != int(n):
        return False
    n = int(n)
    # Miller-Rabin test for prime
    if n == 0 or n == 1 or n == 4 or n == 6 or n == 8 or n == 9:
        return False

    if n == 2 or n == 3 or n == 5 or n == 7:
        return True
    s = 0
    d = n - 1
    while d % 2 == 0:
        d >>= 1
        s += 1
    assert (2 ** s * d == n - 1)

    def trial_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2 ** i * d, n) == n - 1:
                return False
        return True

    for i in range(8):  # number of trials
        a = random.randrange(2, n)
        if trial_composite(a):
            return False

    return True


# Public Parameter Generation
# since p has to be odd, p-1 has to be even and since q has to be odd, k has to be even
def GenerateOrRead(stri):
    print("This will take a while...\n")
    check1 = False
    check2 = False
    q = 0
    p = 0
    g = 0
    while not check1 or not check2:
        while not check1:
            q = random.randrange(pow(2,223), pow(2, 224))
            check1 = True
            count = 0
            while check1 and count < 15:    # Iterate 15 times to increase the likelihood that q is prime
                check1 = is_Prime(q)
                count += 1

        # The smallest possible t, such that it's multiplication with a 224 bit number results in a 2048 bit number is
        # 2^2047(lowest possible 2048 bit number) / (2^224 - 1) (highest possible 224 bit number)
        # ~2^1823
        # The largest t can be calculated as such:
        # 2^2048(lowest possible 2049 bit number) / 2^223 (lowest possible 224 bit number) = 2^1825
        t = pow(2, 1823)    # t is even, since given q and p are odd, p-1 and q*t has to be even
        upper = pow(2,1825)
        while not check2 and t < upper:
            p = t * q + 1
            check2 = True
            count = 0
            while check2 and count < 15:
                check2 = is_Prime(p)    # Iterate 15 times to increase the likelihood that p is prime
                count += 1
            t += 2
    check3 = False
    while not check3:   # Find g
        a = random.randrange(1, p)
        g = pow(a, (p-1) // q, p)
        if g != 1:
            check3 = True

    file = open(stri, "w")
    file.write(str(q) + "\n")
    file.write(str(p) + "\n")
    file.write(str(g) + "\n")

    file.close()

    return q, p, g


# Key Generation
def KeyGen(q, p, g):
    alpha = random.randrange(pow(2, 224), pow(2, 225)) % q

    beta = pow(g, alpha, p)
    return alpha, beta


def random_string(bound):       # generate a string of length bound that consists of random characters
    randstr = ""
    for index in range(bound):
        randstr += chr(random.randrange(32, 127))   # Characters from SPACE to ~
    return randstr


# Signature Generation
def SignGen(message, q, p, g, alpha):
    k = random.randrange(0, q)
    r = pow(g, k, p)
    plaintext = str(message) + str(r)    # Concetanation (//)
    c = str.encode(plaintext)
    h_obj = SHA3_256.new()
    h_obj.update(c)
    h = int(h_obj.hexdigest(), 16)
    s = alpha * h + k
    return s, h


# Signature verification
def SignVer(m, s, h, q, p, g, beta):

    gs = pow(g, s, p)
    invb = modinv(beta, p)  # calculate the inverse of beta
    betah = pow(invb, h, p)
    v = (gs * betah) % p
    m_new = str(m) + str(v)     # Concetanation (//)
    hc_obj = SHA3_256.new()
    hc_obj.update(str.encode(m_new))
    hc = int(hc_obj.hexdigest(),16)
    if hc % q == h:     # Check signature
        return 1
    else:
        return 0

