# coding=utf-8
reset()

# Séparation de l'implémentation et des tests
load("FHE.sage")



def testOP(F, pk=None, sk=None):
    if pk is None or sk is None:
        pk, sk = F.key_gen()
    L = len(F.bases) - 1
    m1 = F.bases[L].R2.random_element()
    m2 = F.bases[L].R2.random_element()
    c1 = F.enc(pk, m1)
    c2 = F.enc(pk, m2)

    print "Testing: "
    print "  Simple encryption/decryption..."
    assert m1 == F.dec(sk, c1, L) and m2 == F.dec(sk, c2, L)

    print "  Opertaions without refresh..."
    assert m1 * m2 == F.bases[L].dec(vector([1, sk[L][1], sk[L][1] ^ 2]),
                                     vector([c1[0] * c2[0], c1[0] * c2[1] + c1[1] * c2[0], c1[1] * c2[1]]))
    assert m1 + m2 == F.dec(sk, c1 + c2, L)

    print "  Scaled ciphertexts can still de decrypted..."
    scaled = F.bases[L - 1].scale(c1)
    target_sk = vector(F.bases[L - 1].Rq, map(lambda x: map(F.bases[L].center_repr, x.list()), sk[L]))
    assert m1 == F.bases[L - 1].dec(target_sk, scaled)

    print "  Bit decomposition compatibility with scalar product..."
    assert F.bases[L].bit_decomp(c1).dot_product(F.bases[L].powers_of_2(sk[L])) == c1.dot_product(sk[L])

    print "  Refresh correctness..."
    refreshed = F.refresh(pk, [c1[0], c1[1], 0], L)
    assert m1 == F.dec(sk, refreshed, L - 1)

    print "  Homomorphic addition  (with refresh)..."
    assert m1+m2 == F.dec(sk, F.add(pk, c1, c2, L), L-1)

    print "  homomorphic multiplication (with refresh)..."
    assert m1*m2 == F.dec(sk, F.mult(pk, c1, c2, L), L-1)

def testRefresh(F, pk=None, sk=None):
    if pk is None or sk is None:
        pk, sk = F.key_gen()
    L = len(F.bases) - 1
    m = F.bases[L].R2.random_element()
    c = F.enc(pk, m)

    for i in reversed(range(1, L + 1)):
        print "level " + str(i)

        assert m == F.dec(sk, c, i)
        c = F.refresh(pk, c, i)


def testLeveledMult(F, pk=None, sk=None):
    if pk is None or sk is None:
        pk, sk = F.key_gen()
    L = len(F.bases) - 1

    for i in reversed(range(2, L+1)):
        print "level " + str(i)
        m1 = F.bases[L].R2.random_element()
        c1 = F.enc(pk, m1, i)
        m2 = F.bases[L].R2.random_element()
        c2 = F.enc(pk, m2, i)

        assert m2 == F.dec(sk, c2, i) and m1 == F.dec(sk, c1, i)
        s_mult = vector([sk[i][0], sk[i][1], sk[i][1] ^ 2])
        c_mult = vector([c1[0]*c2[0], c1[0]*c2[1] + c1[1]*c2[0], c1[1]*c2[1]])
        assert F.bases[i].dec(s_mult, c_mult) == m1*m2
        assert F.dec(sk, F.mult(pk, c1, c2, i), i-1) == m1*m2



def testMaxMult(F, pk=None, sk=None, d=None):
    if pk is None or sk is None:
        pk, sk = F.key_gen()
    L = len(F.bases) - 1
    if d is None:
        d = L

    print "Generating " + str(2^d) + " msg"
    ms = [F.bases[L].R2.random_element() for _ in xrange(2^d)]
    cs = map(lambda m: F.enc(pk, m), ms)
    print "starting"
    for i in reversed(range(L-d+1, L+1)):
        print "level " + str(i)

        c1s = cs[:len(cs)/2]
        c2s = cs[len(cs)/2:]
        m1s = ms[:len(ms)/2]
        m2s = ms[len(ms)/2:]


        cs = map(lambda c1, c2: F.mult(pk, c1, c2, i), c1s, c2s)
        ms = map(lambda m1, m2: m1*m2,                 m1s, m2s)

        for j in xrange(len(cs)):
            assert F.dec(sk, cs[j], i-1) == ms[j]

print "Test parameters can be reused across test functions."
print "The test functions arguments are, in order:"
print " - F is the scheme to be tested (ie. F=FHE(lambda, L) )"
print " - pk, sk are the public and private keys to be used." \
      " If omitted, they will be generated (ie. pk, sk = F.key_gen() )"
print "testOP() checks simple operations validity (dec/enc, basic op, scale, expand, refresh, add/mult with refresh)"
print "testleveledMult() checks that two ciphers can be multiplied and decrypted correctly," \
      " for each level (generating new cipher at each level)"
print "testMaxMult() checks that the biggest multiplication possible with L level can be decrypted correctly." \
      " It generates 2^L ciphertexts and multiply them two by two (thus obtaining 2^(L-1) level L-1 ciphertexts) " \
      " recursively until we reach level 0. Decryption validity is checked at each level." \
      " An additional parameter d can be given to limit testing to d levels, which is a lot quicker."
print ""
print 'Type "F=FHE(10, 5); pk, sk = F.key_gen()" for basic setup.'
