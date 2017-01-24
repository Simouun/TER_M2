reset()

from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler
from sage.stats.distributions.discrete_gaussian_polynomial import DiscreteGaussianDistributionPolynomialSampler




class E_Basic:

    def __init__(self, l, mu):
        self.mu = mu
        """cas RLWE-scheme : n = 1
        n = 1
        N = ceil((2*n + 1)*log(q))"""
        self.N = 3*mu
        self.q = random_prime(2^(self.mu - 1),2^self.mu - 1)
        self.d = 2^l
        #self.X = RealDistribution('gaussian', 3.2)
        P2.<x> = PolynomialRing(GF(2))
        self.R2 = P2.quotient(x^self.d+1)
        Pq.<x> = PolynomialRing(GF(self.q))
        self.Rq = Pq.quotient(x^self.d+1)
        self.X = DiscreteGaussianDistributionPolynomialSampler(self.Rq, self.d+1, 0.5)
        
    def X(self):
        sigma=3.2
        d=DiscreteGaussianDistributionIntegerSampler(sigma, self.q/4 )
        """
        def d_adjust():
            n = d()
            while n > floor(this.q/2) or n < 0:
                n = d()
            return n"""
            
        return self.Rq([d() for _ in xrange(self.d) ])



    def secretKeyGen(self):
        #return [1, self.X.get_random_element()]
        return vector(self.Rq, [1,self.X()])
    
    def publicKeyGen(self, sk):
        AA = random_vector(self.Rq, self.N)
        e = vector(self.Rq, self.N)
        for i in xrange(self.N):
            #e[i] = self.X.get_random_element()
            e[i] = self.X()
        b = AA*sk[1] + 2*e

        pk = matrix(self.Rq, self.N, 2)
        for i in xrange(self.N):
            pk[i,0] = b[i]
            pk[i,1] = -AA[i]
            
        return pk
    
    def enc(self, pk, m):
        r = random_vector(self.R2,self.N)
        rr = vector(self.Rq, map(lambda x: x.list(), r))
        c = vector(self.Rq, [self.R2(m).list(), 0]) + (pk.transpose()*rr)
        return c

    def dec(self, sk, c):
        #return Mod(Mod((c.dot_product(sk)),self.q),2)
        return self.R2(c.dot_product(sk).list())
    
S = E_Basic(5,7)
this =S

sk = S.secretKeyGen()

pk = S.publicKeyGen(sk)

mo = S.R2.random_element() 

c = S.enc(pk,mo)

m = S.dec(sk,c)

print "\non doit retrouver plaintext mo = ",mo
print "\ntest m == mo : ", m == mo
if m == mo:
    print "\non trouve bien m =", m


