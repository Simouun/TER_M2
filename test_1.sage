reset()

from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler


def log(x):
    return log(x, 2)

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

        self.q = random_prime(2^self.mu - 1, lbound=2^(self.mu - 1))
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
        d=DiscreteGaussianDistributionIntegerSampler(sigma, self.q/4, floor(self.q/(2*sigma)) )
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


    def bit_decomp(self, x):
        # type: (self.Rq^n) -> (self.R2^n)^self.q.bit_length())
        """
        decompose a vector x of n elements from Rq to a vector of mu(=q's bit length) elements u_j in R2^n such that:
        sum{2^j*u_j} = x
        :returns a vector of vectors of R2
        """
        def decomp_one(poly):
            ret = [[]] * self.mu
            for coeff in poly.list():
                for i in xrange(self.mu):
                    ret[i].append(coeff % 2)
                    coeff >>= 1

            return map(self.R2, ret)

        return vector(map(vector, matrix(map(decomp_one, x)).columns()))

    def powers_of_2(self, x):
        # type: (self.Rq^n) -> (self.Rq^n)^self.q.bit_length()*n
        """
        :returns the powers of 2 of an Rq^n vector, as a vector of vectors of Rq
        """
        return vector([x*2^j for j in xrange(self.mu)])
    
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

class FHE():
    def __init__(self, _lambda, L):
        mu = log(L) + log(_lambda)
        self.L = L
        self.bases = []
        for j in xrange(L):
            self.bases.append(BasicScheme(_lambda, mu*(j+1)))

    def keygen(self):
        pk = []
        sk = []
        for i in xrange(len(self.bases)):
            scheme = self.bases[i]

            sk_i =scheme.secret_keygen()
            pk_i = scheme.public_keygen(sk)
            sk_i_tensor_decomp = vector(scheme.Rq, scheme.bit_decomp((1, sk_i, sk_i, sk_i^2)))

            hint_i = scheme.public_keygen(s2,len(s1)*mu)
            hint_i[:,1] += scheme.powers_of_2(s1)

            pk.append((pk_i,hint_i))
            sk.append(sk_i)


    def switch_key_gen(self, s1, s2):
        A=self.public_key_gen(s1)

    def enc(self, pk, m):
        return self.bases[-1].enc(pk, m)

    def dec(self, sk, c):
        pass


