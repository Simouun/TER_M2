# coding=utf-8
reset()

# Séparation de l'implémentation et des tests
load("secure_context.sage")

S = BasicScheme(5, 15)
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

#with SecuredContext(5, 2^20) as CipherText, sk:

