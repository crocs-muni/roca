import sympy.ntheory as nt
import random


def prime_default(length=0):
    if length >= 3968:
        return 1427  # real bound 3968
    if length >= 1984:
        return 701  # 701 is used from 1984 rather than 2048
    if length >= 992:
        return 353  # 353 is used from 992 rather than 1024
    if length >= 512:
        return 167
    return 167  # no data for <512, but that doesn't matter anyway


def m_default(length):
    return nt.primorial(prime_default(length), False)


def gord(x):
    return Zmod(x)(65537).multiplicative_order()


def randpri(g=65537, bits=512, M=None, exact_bits=False):
    if M is None:
        M = m_default(bits)

    prime_bits = bits // 2r
    M_bits = log(M, 2r)
    gm = Mod(g, M)  # Zmod ring

    gordm = gord(M)
    max_a = gordm - 1r
    min_a = 2r

    ga = random.randint(min_a, max_a)
    u = lift(gm^ga)  # g^a mod M, almost always lg(M) bits in size

    g_start = floor(prime_bits - M_bits) - 1
    gk_start = 2 ** g_start
    gk_end = 2 ** (g_start+1)

    while True:
        gk = random.randint(gk_start, gk_end)
        w = M * gk
        gp = w + u
        if exact_bits and prime_bits != round(log(gp, 2)):
            continue
        if Integer(gp).is_prime(proof=False):
            # print('gk: 0x%x\nga: 0x%x\ngp: 0x%x' % (gk, ga, gp))
            return int(gk), int(ga), int(gp)


def roca(bits=2048):
    while True:
        p_k, p_a, p = randpri(bits=bits, exact_bits=True)
        q_k, q_a, q = randpri(bits=bits, exact_bits=True)
        N = p * q

        n_bits = ceil(log(N, 2))
        if n_bits == bits:
            return p, q


# print(roca(2048))
