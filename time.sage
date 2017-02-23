# coding=utf-8
reset()

# Séparation de l'implémentation et des tests
load("secure_context.sage")

from time import time


def test():
    ret = []
    for _lambda in xrange(10, 30, 5):
        for L in xrange(5,10):
            cur = {}

            F = FHE(_lambda, L)
            pk, sk = F.key_gen()
            m = F.bases[L].R2.random_element()
            c = F.enc(pk, m)

            for level in xrange(L,1):
                cur["level"] = level
                start = time()
                F.refresh(pk, c, level)
                cur["time"] = time() - start

