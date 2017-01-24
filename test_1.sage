from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler
from sage.stats.distributions.discrete_gaussian_polynomial import DiscreteGaussianDistributionPolynomialSampler


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
        P2.<x> = PolynomialRing(GF(2))
        this.R2 = P2.quotient(x^this.d+1)
        Pq.<x> = PolynomialRing(GF(this.q))
        this.Rq = Pq.quotient(x^this.d+1)
        this.X = DiscreteGaussianDistributionPolynomialSampler(this.Rq, this.d+1, 3.2)

    def secretKeyGen(this):
        #return [1, this.X.get_random_element()]
        return vector(this.Rq, [1,this.X()])
    
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
        rr = vector(this.Rq, map(lambda x: x.list(), r))
        c = vector(this.Rq, [this.R2(m).list(), 0]) + (pk.transpose()*rr)
        return c

    def dec(this, sk, c):
        #return Mod(Mod((c.dot_product(sk)),this.q),2)
        return this.R2(c.dot_product(sk).list())
    
S = E_Basic(5,5)

sk = S.secretKeyGen()

pk = S.publicKeyGen(sk)

mo = S.R2.random_element()

c = S.enc(pk,mo)

m = S.dec(sk,c)

print m == mo



