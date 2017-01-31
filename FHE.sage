# coding=utf-8
from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler

# Antoine (jeudi 27)
# je met des commentaires ici parce que apparement facebook aime vraiment pas que je fasse des converse de groupe (elles disparaissent sans laisser de trace à chaque fois)
# A priori l'histoire de la représentation ne devrait plus être génante. Tout est fait normalement,
# jusqu'au moment du déchiffrement ou on met les coefficients des poly dans la bonne représentation juste avant de faire le modulo 2.
#
# Mais on a toujours des soucis avec le bruit qui est trop grand. Dans notre chiffré, on met une somme de polynôme 'bruit'
# même chaque polynôme généré a toujours ses coeffs dans le bon interval, leur somme en sort généralement.
# Je vois pas trop quoi y faire, vu que normalement vu que la gaussienne est centrée en 0, la somme devrait en rester proche.
# Mais on voit bien le pb si on s'amuse a affiche incrémentalement la somme d'entiers générés, même si chacun est en gros entre -3 et 3,
# on peut en quelques itérations atteindre 20,30, voir 100.
#
# update (lundi 30): en tout cas le schéma de base marche si on augmente la taille de q (à partir de ~15 bits ca marche toujours)
# peut être que c'est lié au fait que HElib utilise une variante plus opti...
# par contre j'ai pas testé l'influence de lambda, mais la mauvaise nouvelle c'est que si on l'augment ça doit foutre le bordel très vite
# ça vient du fait que notre produit de polynôme e_i*r_i sort un polynôme  dont chaque coef est une somme avec un nombre linéaire en d=2^lambda de termes

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
        self.N = 3 * mu

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
        sigma = 3.2
        d = DiscreteGaussianDistributionIntegerSampler(sigma, 0)  # , floor(self.q/(2*sigma)) )
        return self.Rq([d() for _ in xrange(self.d)])

    def secret_key_gen(self):
        return vector(self.Rq, [1, self.X()])

    # TODO: what do when sk is not [1,s'] ? (we have ciphertexts which are valid under bigger keys, for which we need to generate public keys before switching)
    # key_size can be specified for key switch setup, otherwise, the scheme's parameter is used
    def public_key_gen(self, sk, key_size=None):
        # type: (self.Rq^2, int) -> matrix(self.Rq, key_size, 2)
        if key_size == None:
            key_size = self.N
        AA = random_vector(self.Rq, key_size)
        e = vector(self.Rq, [self.X() for _ in xrange(key_size)])

        pk = matrix(self.Rq, key_size, 2)
        pk[:,0] = AA * sk[1] + 2 * e
        pk[:,1] = -AA

        return pk

    def enc(self, pk, m):
        # type: (matrix(self.Rq, self.N, 2), self.R2) -> self.Rq^2
        # r is an random R2 vector, seen as a Rq vector
        r = vector(self.Rq, map(lambda x: x.list(), random_vector(self.R2, self.N)))
        return vector(self.Rq, [self.R2(m).list(), 0]) + (pk.transpose() * r)

    def dec(self, sk, c):
        # type: (self.Rq^2, self.Rq^2) -> self.R2
        def center_repr(coeff):
            if int(coeff) < self.q / 2:
                return int(coeff)
            return int(coeff) - self.q

        return self.R2(map(center_repr, c.dot_product(sk).list()))

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
        return vector(sum(map(list, matrix(map(decomp_one, x)).columns()), []))

    def powers_of_2(self, x):
        # type: (self.Rq^len(x)) -> self.Rq^(len(x)*self.q.bit_length())
        """
        :returns the mu powers of 2 of an Rq^n vector, as a Rq^(n*mu) vector
        """
        return vector([x[i] * 2 ^ j for j in xrange(self.mu) for i in xrange(len(x))])

    def switch_key_gen(self, s1, s2):
        # type: (self.Rq^len(s1), self.Rq^len(s2)) -> matrix(self.Rq, len(s1)*self.q.bit_length(), 2)
        """
        generate hint to be used later by switch_key() procedure to switch a ciphertext to key s1 to key s2.
        Here the keys may not directly come from priavet_key_gen(), ie. s1 is
        """
        hint = self.public_key_gen(s2, len(s1) * self.mu)
        hint[:, 0] += self.powers_of_2(s1)
        return hint

    def switch_key(self, c, hint):
        # type: (self.Rq^len(c), matrix(self.Rq, len(c)*self.q.bit_length(), hint.ncols())) -> self.Rq^hint.ncols()
        return  self.bit_decomp(c).transpose()*hint


# TODO: check this
def scale(x, q, p, r=2):
    scale = p / q
    ret = []
    for poly in x:
        scaled_poly = []
        for coef in poly.list():
            scaled = coef*scale
            scaled_poly.append(scaled - scaled%r + coef%r)

        ret.append(poly.parent()(scaled_poly))

    return vector(ret)



class FHE:
    def __init__(self, _lambda, L):
        mu = log(L) + log(_lambda)
        self.L = L
        self.bases = []
        for j in reversed(xrange(L+1)):
            self.bases.append(BasicScheme(_lambda, mu * (j + 1)))

    def key_gen(self):
        pk = []
        sk = []
        for j in reversed(xrange(len(self.bases))):
            scheme = self.bases[j]

            sk_j = scheme.secret_keygen()
            pk_j = scheme.public_keygen(sk)

            hint_j = None
            if j != self:
                sk_j_decomp = scheme.bit_decomp((scheme.Rq(1), sk_j, sk_j, sk_j ^ 2))
                hint_j = scheme.switch_key_gen(vector(scheme.Rq, sk_j_decomp.list()), sk[-1])

            pk.append({"pk":pk_j, "hint":hint_j})
            sk.append(sk_j)

        return pk, sk

    def enc(self, pk, m):
        return self.bases[-1].enc(pk, m)

    # todo: pack the ciphertext and its level
    def dec(self, sk, c, j):
        return self.bases[j].dec(sk[j], c)

    def add(self, pk, c1, c2, j):
        return  self.refresh(pk, c1+c2, j)

    #todo
    def mult(self, pk, c1, c2, j):
        pass

    def refresh(self, pk, c, j):
        c1 = self.bases[j].powers_of_2(c1)
        c2 = scale(c1, self.bases[j].q, self.bases[j-1].q)
        c3 = self.bases[j-1].switch_key(c2, pk[j-1]["hint"])
        return c3

