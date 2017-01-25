reset()

from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler




class BasicScheme:

    def __init__(self, _lambda, mu):
        """
        represents one instance of the basic cryptosystem
        :param _lambda: security parameter
        :param mu: modulus size
        self.q is the modulus
        self.d the ring dimension
        self.Rn is the ring of polynomials with coefficients in Z/nZ modulo f=x^d+1
        self.N is the size parameter (?)
        """
        self.mu = mu
        """cas RLWE-scheme : n = 1
        N = ceil((2*n + 1)*log(q))"""
        self.N = 3*mu

        self.q = random_prime(2^(self.mu - 1),2^self.mu - 1)
        self.d = 2^_lambda
        P2.<x> = PolynomialRing(GF(2))
        self.R2 = P2.quotient(x^self.d+1)
        Pq.<x> = PolynomialRing(GF(self.q))
        self.Rq = Pq.quotient(x^self.d+1)

    def X(self):
        """
        noise generator, from gaussian distribution
        :return: random Rq element, with (infinite) norm lower that q/2
        """
        sigma=3.2
        d=DiscreteGaussianDistributionIntegerSampler(sigma, self.q/4 )
        return self.Rq([d() for _ in xrange(self.d) ])



    def secret_key_gen(self):
        return vector(self.Rq, [1,self.X()])
    
    def public_key_gen(self, sk):
        AA = random_vector(self.Rq, self.N)
        e = vector(self.Rq, self.N)
        for i in xrange(self.N):
            e[i] = self.X()
        b = AA*sk[1] + 2*e

        pk = matrix(self.Rq, self.N, 2)
        for i in xrange(self.N):
            pk[i,0] = b[i]
            pk[i,1] = -AA[i]
            
        return pk
    
    def enc(self, pk, m):
        #r is an random R2 vector, seen as a Rq vector
        r = vector(self.Rq, map(lambda x: x.list(), random_vector(self.R2,self.N))) # r seen as a Rq vector
        return vector(self.Rq, [self.R2(m).list(), 0]) + (pk.transpose()*r)


    def dec(self, sk, c):
        return self.R2(c.dot_product(sk).list())
    
S = BasicScheme(5,7)
self =S

sk = S.secret_key_gen()

pk = S.public_key_gen(sk)

mo = S.R2.random_element() 

c = S.enc(pk,mo)

m = S.dec(sk,c)

print "\non doit retrouver plaintext mo = ",mo
print "\ntest m == mo : ", m == mo
if m == mo:
    print "\non trouve bien m =", m


