
"""
#taille de q
#mu =
#bit entre 0 et 1 pour LWE ou RLWE
b = r
#anneau pour RLWE
P.<x> = PolynomialRing(GF(2))
f = x^d + 1
R = P.quotient(f)

#d = power of 2

#distribution gaussienne
sigma = 1
X = RealDistribution('gaussian', sigma)
"""

class E_Basic:

    def __init__(this, l, mu):
        this.mu = mu
        """cas RLWE-scheme : n = 1
        n = 1
        N = ceil((2*n + 1)*log(q))"""
        this.N = 3*mu
        this.q = randrange(2^(mu - 1),2^mu - 1)
        this.d = 2^l
        this.X = RealDistribution('gaussian', 3.2)
        P2.<x> = PolynomialRing(GF(2))
        this.R2 = P2.quotient(x^this.d+1)
        Pq.<x> = PolynomialRing(GF(q))
        this.Rq = Pq.quotient(x^this.d+1)
    

    def secretKeyGen(this):
        return [1, this.X.get_random_element()]

    def publicKeyGen(this, sk):
        AA = random_vector(this.Rq, this.N)
        e = vector(this.R, N)
        for i in xrange(this.N):
            e[i] = this.X.get_random_element()
        b = AA*sk[1] + 2*e

        pk = matrix(Rq, this.N, 2)
        for i in xrange(this.N):
            pk[i,0] = b[i]
            pk[i,1] = -AA[i]
            
        return pk
    
    def enc(this, pk, m):
        pass


S = E_Basic(50,50)
