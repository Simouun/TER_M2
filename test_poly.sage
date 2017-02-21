

load("secure_context.sage")
boole = 0
 
if boole :
    L = 5
    F = FHE(10, L)
    pk, sk = F.key_gen()
    m = F.bases[L].R2.random_element()
    c = F.enc(pk, m)


Ring = Rq(4,3)
p = Ring.random_element()


def polyeval(c,m,p):
    print c
    
    c1 = copy(c)
    lp = p.list()
    print p.list()

    hc = 0

    for i in range(1,len(lp)):
        print lp[i]
        if i != 1:
            print "c1 = ",parent(c1)
            c1 = F.mult(pk,c1,c,6-i)
            
        if lp[i] != 0:
            while lp[i] != 0:
                hc = hc + c
                lp[i] -= 1
                print "saucisse"

    return hc



var1 = c
var2 = F.mult(pk,var1,var1,5)

var1 = F.refresh(pk,var1,5)
var3 = F.mult(pk,var2,var1,4)

#var3 = var3 + var3 #F.add(pk,var3, var3, 3)

message = m**3
