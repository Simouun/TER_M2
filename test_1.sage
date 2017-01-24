from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler
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
        this.q = random_prime(2^(this.mu - 1),2^this.mu - 1)
        this.d = 2^l
        #this.X = RealDistribution('gaussian', 3.2)
        this.X = DiscreteGaussianDistributionIntegerSampler(3.2)
        P2.<x> = PolynomialRing(GF(2))
        this.R2 = P2.quotient(x^this.d+1)
        Pq.<x> = PolynomialRing(GF(this.q))
        this.Rq = Pq.quotient(x^this.d+1)
    

    def secretKeyGen(this):
        #return [1, this.X.get_random_element()]
        return [1,this.X()]
    
    def publicKeyGen(this, sk):
        AA = random_vector(this.Rq, this.N)
        e = vector(this.Rq, this.N)
        for i in xrange(this.N):
            #e[i] = this.X.get_random_element()
            e[i] = this.X()
        b = AA*sk[1] + 2*e

        pk = matrix(this.Rq, this.N, 2)
        for i in xrange(this.N):
            pk[i,0] = b[i]
            pk[i,1] = -AA[i]
            
        return pk
    
    def enc(this, pk, m):
        r = random_vector(this.R2,this.N)
        print r
        c = m + (pk.transpose()*vector(this.Rq,r))
        return c

    def dec(this, sk, c):
        return Mod(Mod((c.dot_product(sk)),this.q),2)

S = E_Basic(5,5)

sk = S.secretKeyGen()

pk = S.publicKeyGen(sk)

c = S.enc(pk,(1,0))

m = S.dec(sk,c)

print m
