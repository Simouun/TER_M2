# coding=utf-8
reset()

# Séparation de l'implémentation et des tests
load("secure_context.sage")


S=BasicScheme(5,15)
sk1 = S.secret_key_gen()
pk1 = S.public_key_gen(sk1)
sk2 = S.secret_key_gen()
mo = S.R2.random_element()
c = S.enc(pk1, mo)
c2 = S.switch_key(c, S.switch_key_gen(sk1,sk2))

assert mo == S.dec(sk1, c)
assert mo == S.dec(sk2, c2)
