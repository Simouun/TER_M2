#Basic RLWE-Based Encryption Scheme

#parametre de securite
landa =
#taille de q
mu =
#bit entre 0 et 1 pour LWE ou RLWE
b = randint(0,1)
#anneau pour RLWE
R.<x> = PolynomialRing(GF(2))

d = power of 2
f = x^d + 1
q = 

#distribution gaussienne
sigma = 1
X = RealDistribution('gaussian', sigma)



def E_Setup(1^landa, 1^mu):
    params = []
    """cas RLWE-scheme : n = 1
    n = 1
    N = ceil((2*n + 1)*log(q))"""
    N = 3*log(q)
    params += N
    
    return params

def E_SecretKeyGen(params):
    s = []
    for i in range(n-1):
        s[i] = X.get_random_element()
    print "s = ",s

    sk = []
    sk[0] = 1
    for j in range(1,n-1):
        sk[j] = s[j]

    return sk
