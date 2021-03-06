# coding=utf-8
load("secure_context.sage")
boole = 0


if boole:
    L = 10
    
    F = FHE(5, L)
    pk, sk = F.key_gen()
    m1 = F.bases[L].R2.random_element()
    m2 = F.bases[L].R2.random_element()
    c1 = F.enc(pk, m1)
    c2 = F.enc(pk, m2)

#test multiplication simple
cipher = F.mult(pk,c1,c2,L)
assert m1*m2 == F.bases[L].dec(vector([1,sk[L][1],sk[L][1]**2]),vector([c1[0] * c2[0], c1[0] * c2[1] + c1[1] * c2[0], c1[1] * c2[1]]))


if 1:
    listm = [F.bases[L].R2.random_element() for _ in xrange(16)]
    

    listc1 = [F.enc(pk, listm[i]) for i in range(8)]
    listc2 = [F.enc(pk, listm[i]) for i in range(8,16)]
    listmult = []
    C = 0


#Test multiplication sur plusieurs niveaux
    
print "Starting"
cipher1 = F.mult(pk, listc1[0], listc1[1], L)
print "mult1 fini"
cipher2 = F.mult(pk, listc1[2], listc1[3], L)
print "mult2 fini"
cipher3 = F.mult(pk, listc1[4], listc1[5], L)
print "mult3 fini"
cipher4 = F.mult(pk, listc1[6], listc1[7], L)
print "mult4 fini"

#checking everything is fine:

check1 = listm[0]*listm[1]
check2 = listm[2]*listm[3]
check3 = listm[4]*listm[5]
check4 = listm[6]*listm[7]

assert check1 == F.dec(sk,cipher1,L-1)
print "deciph1 fini"
assert check2 == F.dec(sk,cipher2,L-1)
print "deciph2 fini"
assert check3 == F.dec(sk,cipher3,L-1)
print "deciph3 fini"
assert check4 == F.dec(sk,cipher4,L-1)
print "deciph4 fini"

print "Premiere mult checked"


cipher12 = F.mult(pk, cipher1, cipher2, L-1)
print "mult12 fini"

cipher34 = F.mult(pk, cipher3, cipher4, L-1)
print "mult34 fini"


check12 = check1*check2
check34 = check3*check4


assert check34 == F.dec(sk, cipher34, L-2)
print "deciph34 fini"
assert check12 == F.dec(sk, cipher12, L-2)
print "deciph12 fini"
print "Deuxieme mult checked"


check123 = check1*check2*check3

cipher3 = F.refresh(pk,cipher3,L-1)

cipher123 = F.mult(pk, cipher12, cipher3, L-2)

assert check123 == F.dec(sk, cipher123, L-3)



cipher1234 = F.mult(pk, cipher12, cipher34, L-2)
print "mult1234 fini"


check1234 = listm[0]*listm[1]*listm[2]*listm[3]*listm[4]*listm[5]*listm[6]*listm[7]

assert check1234 == F.dec(sk, cipher1234, L-3)
print "deciph1234 fini"
print "Troisieme mult checked"


print "Premiere etape"



c1,c2,c3,c4,c5,c6,c7,c8 = listc1[0],listc1[1],listc1[2],listc1[3],listc1[4],listc1[5],listc1[6],listc1[7]

m1,m2,m3,m4,m5,m6,m7,m8 = listm[0],listm[1],listm[2],listm[3],listm[4],listm[5],listm[6],listm[7]

#Test multiplication successive une à une
def test():
    cipher12 = F.mult(pk, c1, c2, L)

    assert m1*m2 == F.dec(sk,cipher12,L-1)

    c3,c4,c5,c6,c7= F.refresh(pk,c3,L),F.refresh(pk,c4,L),F.refresh(pk,c5,L),F.refresh(pk,c6,L),F.refresh(pk,c7,L)


    cipher123 = F.mult(pk, cipher12,c3,L-1)

    assert m1*m2*m3 == F.dec(sk,cipher123,L-2)

    c4,c5,c6,c7= F.refresh(pk,c4,L-1),F.refresh(pk,c5,L-1),F.refresh(pk,c6,L-1),F.refresh(pk,c7,L-1)

    cipher1234 = F.mult(pk, cipher123,c4,L-2)

    assert m1*m2*m3*m4 == F.dec(sk,cipher1234,L-3)

    c5,c6,c7=F.refresh(pk,c5,L-2),F.refresh(pk,c6,L-2),F.refresh(pk,c7,L-2)

    cipher12346 = F.mult(pk, cipher1234,c6,L-3)

    assert m1*m2*m3*m4*m6 == F.dec(sk,cipher12346,L-4)



