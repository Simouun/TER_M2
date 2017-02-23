# coding=utf-8
reset()

# Séparation de l'implémentation et des tests
load("secure_context.sage")

"""
S=BasicScheme(2^7,15)
sk1 = S.secret_key_gen()
pk1 = S.public_key_gen(sk1)
sk2 = S.secret_key_gen()
mo = S.R2.random_element()
c = S.enc(pk1, mo)
c2 = S.switch_key(c, S.switch_key_gen(sk1,sk2))

assert mo == S.dec(sk1, c)
assert mo == S.dec(sk2, c2)
"""

L = 4
F = FHE(5, L)
pk, sk = F.key_gen()
m1 = F.bases[L].R2.random_element()
m2 = F.bases[L].R2.random_element()
c1 = F.enc(pk, m1)
c2 = F.enc(pk, m2)

# simple encryption/decryption
assert m1 == F.dec(sk, c1, L) and m2 == F.dec(sk, c2, L)

# opertaions works without refresh
assert m1 * m2 == F.bases[L].dec(vector([1, sk[L][1], sk[L][1] ^ 2]),
                                 vector([c1[0] * c2[0], c1[0] * c2[1] + c1[1] * c2[0], c1[1] * c2[1]]))
assert m1 + m2 == F.dec(sk, c1 + c2, L)

# A scaled ciphertext can still de decrypted
scaled = F.bases[L - 1].scale(c1) 
target_sk = vector(F.bases[L - 1].Rq, map(lambda x: map(F.bases[L].center_repr, x.list()), sk[L]))
assert m1 == F.bases[L - 1].dec(target_sk, scaled)

# decomposition is compatible with scalar product
assert F.bases[L].bit_decomp(c1).dot_product(F.bases[L].powers_of_2(sk[L])) == c1.dot_product(sk[L])

"""
# simple key switching
S=BasicScheme(5,15)
sk1 = S.secret_key_gen()
pk1 = S.public_key_gen(sk1)
sk2 = S.secret_key_gen()
mo = S.R2.random_element()
c = S.enc(pk1, mo)
cc = S.switch_key(c, S.switch_key_gen(sk1,sk2))
assert mo == S.dec(sk2, cc)
"""

refreshed = F.refresh(pk, [c1[0], c1[1], 0], L)
assert m1 == F.dec(sk, refreshed, L - 1)

# homomorphic addition works (with refresh)
assert m1+m2 == F.dec(sk, F.add(pk, c1, c2, L), L-1)

# homomorphic multiplication works (with refresh)
assert m1*m2 == F.dec(sk, F.mult(pk, c1, c2, L), L-1)
