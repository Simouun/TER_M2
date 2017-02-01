
load("FHE.sage")


class SecuredContext:
    """
    This class helps keeping track of every parameters.
    """

    def __init__(self, _lambda, L):
        self.scheme = FHE(_lambda, L)
        self.pk, self.sk = self.scheme.key_gen()
        self.CipherText = cipher_class_factory(self.scheme, self.pk)
        self.PlainText = Rq(d, 2)

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

        def __init__(self, plaintext):
            self.cipher = scheme.enc(pk, plaintext)
            self.j = scheme.L

        def decrypt(self, sk):
            return scheme.dec(sk, self.cipher, self.j)

        def __iadd__(self, other):
            if self.j > other.j:
                self.refresh(self.j - other.j)
            if self.j < other.j:
                other = copy(other).refresh(other.j - self.j)

            self.cipher = scheme.add(pk, self.cipher, other.cipher, self.j)

        def __add__(self, other):
            # small optimisation to make less copies
            (new, o) = (copy(self), other) if self.j >= other.j else (copy(other), self)
            new += o
            return new

        def __imul__(self, other):
            if self.j > other.j:
                self.refresh(self.j - other.j)
            if self.j < other.j:
                other = copy(other).refresh(other.j - self.j)

            self.cipher = scheme.mult(pk, self.cipher, other.cipher, self.j)

        def __mul__(self, other):
            (new, o) = (copy(self), other) if self.j >= other.j else (copy(other), self)  # same
            new *= o
            return new

        def refresh(self, n=1):
            """
            Refreshes n times a ciphertext (in-place modification)
            :return: the refreshed ciphertext, for chaining
            """
            if self.j < n:
                raise ArithmeticError("Can't refresh "+str(n)+" times a level "+str(self.j)+" cipher")
            for _ in xrange(n):
                self.cipher = scheme.refresh(pk, self.cipher, self.j)
                self.j -= 1

            return self


    return CipherText
