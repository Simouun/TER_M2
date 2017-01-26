reset()

from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler


def log(x):
    return log(x, 2)

class BasicScheme:

    def __init__(self, _lambda, mu):
        """
        represents one instance of the basic cryptosystem
        :param _lambda: security parameter
        :param mu: modulus size (in bits)
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

    #key_size can be specified for key switch setup
    def public_key_gen(self, sk, key_size=self.N):
        AA = random_vector(self.Rq, key_size)
        e = vector(self.Rq, key_size)
        for i in xrange(key_size):
            e[i] = self.X()
        b = AA*sk[1] + 2*e

        pk = matrix(self.Rq, key_size, 2)
        for i in xrange(key_size):
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
        # type: (self.Rq^len(x)) -> self.R2^(len(x)*self.q.bit_length())
        """
        decompose a vector x of n elements from Rq to a vector of n*mu elements u_ij in R2 such that:
        sum_j{2^j*u_ij} = x_i (for all i in range(n))
        :returns a vector of R2
        """
        def decomp_one(poly):
            ret = [[]] * self.mu
            for coeff in poly.list():
                for i in xrange(self.mu):
                    ret[i].append(coeff % 2)
                    coeff >>= 1

            return map(self.R2, ret)

        # the matrix has the elements we want in the right place.
        # we convert it to a big vector of all columns concatenated.
        return  vector(sum(map(list, matrix(map(decomp_one, x)).columns()), []))

    def powers_of_2(self, x):
        # type: (self.Rq^len(x)) -> self.Rq^(len(x)*self.q.bit_length())
        """
        :returns the mu powers of 2 of an Rq^n vector, as a Rq^(n*mu) vector
        """
        return vector([x[i]*2^j for j in xrange(self.mu) for i in xrange(len(x))])

    def switch_key_gen(self, s1,s2):
        hint = self.public_key_gen(s2, len(s1)*self.mu)
        hint[0,:] += self.powers_of_2(s1)
        return hint

#TODO: check this
def scale(x, q, p, r=2):
    scale = p/q
    ret = []
    for poly in x:
        scaled_poly = []
        for coef in poly.list():
            scaled = round(coef*scale)
            scaled += ((scaled % r) -( coef % r))
            scaled_poly.append(scaled)
        ret.append(poly.parent()(scaled_poly))

    return vector(ret)

S = BasicScheme(5,7)
self =S
[]
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
        for j in reversed(xrange(L)):
            self.bases.append(BasicScheme(_lambda, mu*(j+1)))

    def key_gen(self):
        pk = []
        sk = []
        for j in xrange(len(self.bases)):
            scheme = self.bases[j]

            sk_j =scheme.secret_keygen()
            pk_j = scheme.public_keygen(sk)

            sk_j_tensor_decomp = vector(scheme.Rq, scheme.bit_decomp((scheme.Rq(1), sk_j, sk_j, sk_j^2)))
            hint_j = scheme.switch_key_gen(sk_j_tensor_decomp, sk[-1]) if j != len(self.bases)-1 else None

            pk.append((pk_j,hint_j))
            sk.append(sk_j)

        return pk, sk

    def enc(self, pk, m):
        return self.bases[-1].enc(pk, m)

    #todo: pack the ciphertext and its level
    def dec(self, sk, c, j):
        return self.bases[j].dec(sk[j], c)

