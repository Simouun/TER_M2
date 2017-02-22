
load("FHE.sage")


class SecuredContext:
    """
    This class helps keeping track of every parameters.
    """

    def __init__(self, _lambda, L):
        self.scheme = FHE(_lambda, L)
        self.pk, self.sk = self.scheme.key_gen()
        self.CipherText = cipher_class_factory(self.scheme, self.pk)
        self.PlainText = Rq(self.scheme.d, 2)

    def __call__(self, *args):
        """
        convert plaintext their homomorphic version
        :param args: elements to be converted
        :returns: a mapping of the arguments to their homomorphic version
        """
        ret = []
        for arg in args:
            if arg.parent() == self.PlainText:
                ret.append(self.CipherText(arg))  # data is converted to ciphertext
            else:
                ret.append(arg)  # default, do nothing
        return ret


def cipher_class_factory(scheme, pk):
    """
    This factory create a class allow easy manipulation of ciphertexts
    cipher level and public keys are automatically handled
    instances of this class support addition and multiplication as homomorphic operations
    :param scheme: the scheme instantiation to be used
    :param pk: the public key common to all ciphertexts
    :return: The class representing a ciphertext
    """

    # TODO: store each known cipher data for a given level, and make some optimisations
    class CipherText:

        def __init__(self, plaintext, level=scheme.L):
            self.cipher = scheme.enc(pk, plaintext, level)
            self.level = level

        def decrypt(self, sk):
            return scheme.dec(sk, self.cipher, self.level)

        def __iadd__(self, other):
            if self.level > other.level:
                self.refresh(self.level - other.level)
            if self.level < other.level:
                other = copy(other).refresh(other.level - self.level)

            self.cipher = scheme.add(pk, self.cipher, other.cipher, self.level)
            self.level -=1

        def __add__(self, other):
            # small optimisation to make less copies
            (new, o) = (copy(self), other) if self.level >= other.level else (copy(other), self)
            new += o
            return new

        def __imul__(self, other):
            if self.level > other.level:
                self.refresh(self.level - other.level)
            if self.level < other.level:
                other = copy(other).refresh(other.level - self.level)

            self.cipher = scheme.mult(pk, self.cipher, other.cipher, self.level)
            self.level -= 1

        def __mul__(self, other):
            (new, o) = (copy(self), other) if self.level >= other.level else (copy(other), self)  # same
            new *= o
            return new

        def refresh(self, n=1):
            """
            Refreshes n times a ciphertext (in-place modification)
            :return: the refreshed ciphertext, for chaining
            """
            if self.level < n:
                raise ArithmeticError("Can't refresh " + str(n) + " times a level " + str(self.level) + " cipher")
            for _ in xrange(n):
                self.cipher = scheme.refresh(pk, self.cipher, self.level)
                self.level -= 1

            return self

    return CipherText

"""
SC = SecuredContext(10, 4)
m1 = SC.PlainText.random_element()
m2 = SC.PlainText.random_element()
c1 = SC.CipherText(m1)
c2 = SC.CipherText(m2)

assert (c1*c2).decrypt(SC.sk) == m1*m2
assert (c1+c2).decrypt(SC.sk) == m1+m2
"""
