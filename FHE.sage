# coding=utf-8
from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler

# Antoine (jeudi 27)# je met des commentaires ici parce que apparement facebook aime vraiment pas que je fasse des converse de groupe (elles disparaissent sans laisser de trace à chaque fois)
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

def log2(x):
    return log(x, 2)

def Rq(d, q):
    # type: (int, int) -> Rq
    """
    :return: The R_q ring
    """
    Pq.<x> = PolynomialRing(GF(q))
    return Pq.quotient(x^d + 1)


def center_repr(coeff, q):
    coeff = int(coeff)
    if coeff < q / 2:
        return coeff
    return coeff - q

class BasicScheme:

    def __init__(self, dim, bound, mu):
        """
        represents one instance of the basic cryptosystem
        :param mu: modulus size (in bits)
        :param dim: is the ring dimension, should be big enough to guarantee 2^lambda security
        self.q is the modulus
        self.Rn is the ring of polynomials with coefficients in Z/nZ modulo f=x^d+1
        self.N is the size parameter (?)
        dim is given instead of lambda because it needs to be consistent with the whole cryptosystem
        Note: dim is sufficient to parametrize security for the basic scheme, assuming that mu is correctly set
        """
        print "Init BasicScheme from dim="+str(dim)+", bound="+str(bound)+", mu="+str(mu)+" ..."
        self.mu = mu
        self.q = random_prime(2^mu - 1, lbound=2^(mu - 1))
        self.N = ceil(3*log2(self.q)) # N = ceil((2*n + 1)*log(q)), n=1 for RLWE

        # we keep R2 reference for convenience
        self.R2 = Rq(dim, 2)
        # /!\ sage takes quite some time computing this one when dim and q are both big
        self.Rq = Rq(dim, self.q)

        tau=3
        distribution = DiscreteGaussianDistributionIntegerSampler(bound/tau, 0 , tau) # sigma*tau=bound
        def X():
            """
            noise generator, from gaussian distribution
            :return: random Rq element, with (infinite) norm lower that bound
            """
            poly = [distribution() for _ in xrange(dim)]
            return self.Rq(poly)
            n = sum(map(lambda coef: int(bool(coef)), poly))
            if n != 0:
                print str(n)+" coefs != 0"
            return self.Rq(poly)
        self.X = X


    def secret_key_gen(self):
        v= vector(self.Rq, [1, self.X()])
        print "method "+str(v)
        return v

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

        return self.R2(map(self.center_repr, c.dot_product(sk).list()))

    def bit_decomp(self, x):
        # type: (self.Rq^len(x)) -> self.Rq^(len(x)*self.q.bit_length())
        # the return type base is in fact R2, but the elements are seen as in Rq
        """
        decompose a vector x of n elements from Rq to a vector of n*mu elements u_ij in R2 such that:
        sum_j{2^j*u_ij} = x_i (for all i in range(n))
        :returns: the (u_ij) vector
        """
        
        def decomp_one(poly):
            ret = [ [] for _ in xrange(self.mu) ]
            for coeff in poly.list():
                coeff = Integer(coeff)
                for i in xrange(self.mu):
                    ret[i].append(coeff % 2)
                    coeff >>= 1

            return map(self.Rq, ret)

        # the matrix has the elements we want in the right place.
        # we convert it to a big vector of all columns concatenated.
        return vector(self.Rq, sum(map(list, matrix(map(decomp_one, x)).columns()), []))

    def powers_of_2(self, x):
        # type: (self.Rq^len(x)) -> self.Rq^(len(x)*self.q.bit_length())
        """
        :returns the mu powers of 2 of an Rq^n vector, as a Rq^(n*mu) vector
        """
        return vector([self.Rq(x[i].list()) * 2 ^ j for j in xrange(self.mu) for i in xrange(len(x))])

    # important: sk2 has to be a 'canonical' dimension 2 key = [1,s'] and must be in self.Rq
    def switch_key_gen(self, sk1, sk2):
        # type: (self.Rq^len(sk1), self.Rq^2) -> matrix(self.Rq, len(sk1)*self.q.bit_length(), 2)
        """
        generate hint to be used later by switch_key() procedure to switch a ciphertext to key sk1 to key sk2.
        Here the sk1 may not directly come from private_key_gen(), ie. sk1 = sk' tensor sk'
        sk2 however MUST not be modified (ie. sk2 = private_key_gen())
        """
        hint = self.public_key_gen(sk2, len(sk1) * self.mu)
        hint[:, 0] = hint.column(0) + self.powers_of_2(sk1)
        return hint

    def switch_key(self, c, hint):
        # type: (self.Rq^len(c), matrix(self.Rq, len(c)*self.q.bit_length(), 2)) -> self.Rq^2
        """
        Does the actual key switching for a given ciphertext
        """
        return   self.bit_decomp(c)*hint


    def scale(self, x):
        # type: (Rp^len(x)) -> self.Rq^len(x)
        """
        Scale a vector while preserving mod-2 congruency
        The elements are scaled from their modulus (p) to self.q modulus
        :param x: the mod p vector to be scaled
        :returns: the closest to x, mod-q vector, congruent to x mod 2
        """
        p = x.base_ring().characteristic()
        scale = self.q / p
        ret = []
        for poly in x:
            scaled_poly = []
            for coef in poly.list():
                coef = center_repr(coef, p)
                scaled = floor(coef*scale)
                if scaled%2 != coef%2:
                    scaled +=1

                scaled_poly.append(scaled)

            ret.append(self.Rq(scaled_poly))

        return vector(ret)


    def center_repr(self, coeff):
        """
        :param coeff: a Z/qZ element
        :return:  the 0-centered integer representing coeff
        """
        return center_repr(coeff, self.q)

    def __str__(self):
        return "Basic Sheme with modulus "+str(self.q)+" (size "+str(self.mu)+"), N is "+str(self.N)+", dimension is "+str(self.Rq.modulus().degree())


class FHE:
    def __init__(self, _lambda, L):
        mu = floor(log2(L) + log2(_lambda))
        self.L = L
        # we store d because we may need it later on
        self.d = 2^floor(log2(mu*L*_lambda)-1) # dim = 2^x ~= mu*L*lambda
        # because the lowest modulo is sometimes a bit small, we skip the first step.
        # increasing the step  ( mu) would be much more costly
        self.bases = [ BasicScheme(self.d, 3.2, mu * (j + 2)) for j in xrange(L+1) ] # bound should be 2^(mu-2)*self.d^-2



    def key_gen(self):
        """
        Generate the public and privates keys, as two arrays of BasicScheme's public and private keys,
        plus the key switching hints.
        hint_j allow to switch from the (modified) sk_j to the (original) sk_{j-1}
        :returns: [ {"pk": pk_j, "hint": hint_j} ],  sk_j ]
        """
        pk = [None]*len(self.bases)
        sk = [None]*len(self.bases)
        for j in reversed(xrange(len(self.bases))):
            scheme = self.bases[j]
            print scheme
            print "Generating keys..."
            print "    private"
            cur_sk = scheme.secret_key_gen()
            print "    cur= "+str(cur_sk)
            print "    public"
            cur_pk = { "pk": scheme.public_key_gen(cur_sk) }
            
            if j != self.L:
                # note : we don't use exactly the tensor product sk * sk, because with RLWE instantiation we know that
                # sk is of dimension 2. Therefore, we can remove the redundant coef (= sk) and set the multiplied
                # ciphertext vector accordingly (see add() and mult() )
                print "    hint"
                sk_decomp = self.bases[j+1].bit_decomp((sk[j+1][0], sk[j+1][1], sk[j+1][1] ^ 2))
                cur_pk["hint"] = scheme.switch_key_gen(sk_decomp, cur_sk)

            pk[j] = cur_pk
            sk[j] = cur_sk

        return pk, sk

    def enc(self, pk, m, j=None):
        if j == None:
            j = self.L
        return self.bases[j].enc(pk[j]["pk"], m)

    def dec(self, sk, c, j):
        return self.bases[j].dec(sk[j], c)

    def add(self, pk, c1, c2, j):
        # the ciphertext has to be valid under the corresponding sk_decomp in key_gen() (ignoring bit_decomp )
        # refresh will switch it to the right key
        c3 = vector([c1[0]+c2[0], c1[1]+c2[1], 0])
        return  self.refresh(pk, c3, j)


    def mult(self, pk, c1, c2, j):
        # same, we don't use the tensor c1 * c2 because the middle coef will be multiplied by the same factor (= sk)
        # So the addition is done beforehand, in here, and we use it as a unique coef
        c3 = vector([c1[0]*c2[0], c1[0]*c2[1] + c1[1]*c2[0], c1[1]*c2[1]])
        return self.refresh(pk, c3, j)

    def refresh(self, pk, c, j):
        if len(c) == 2:
            c = vector([c[0], c[1], 0])
        c1 = self.bases[j].powers_of_2(c)
        c2 = self.bases[j-1].scale(c1) # scale to j-1 modulus
        c3 = self.bases[j-1].switch_key(c2, pk[j-1]["hint"])
        return c3

