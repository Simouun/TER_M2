# coding=utf-8
reset()

# Séparation de l'implémentation et des tests

load("FHE.sage")

S = BasicScheme(5, 20)
self = S

sk = S.secret_key_gen()

pk = S.public_key_gen(sk)

mo = S.R2.random_element()

c = S.enc(pk, mo)

m = S.dec(sk, c)

print "\non doit retrouver plaintext mo = ", mo
print "\ntest m == mo : ", m == mo
if m == mo:
    print "\non trouve bien m =", m
