# coding=utf-8
reset()

# Séparation de l'implémentation et des tests
load("FHE.sage")

from time import time


def test(_lambda,L):
    ret = []
    #for _lambda in xrange(10, 20, 5):
    #for L in xrange(5,10):
    for _ in range(10):
        cur = {}

        F = FHE(_lambda, L)
        pk, sk = F.key_gen()
        m = F.bases[L].R2.random_element()
        c = F.enc(pk, m)
        for level in xrange(L,1,-1):
            cur["dim"] = F.d
            cur["mu"] = F.bases[level].mu
            cur["level"] = level
            start = time()
            F.refresh(pk, c, level)
            cur["time"] = time() - start
            ret = ret + [copy(cur)]

    print ret


