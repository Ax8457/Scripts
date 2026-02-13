##https://cryptohack.org/courses/elliptic/ecc1/
## https://cryptohack.org/courses/elliptic/ecc2/
## https://cryptohack.org/courses/elliptic/ecc3/
## Point addition
## Scalar Multiplication
## Share Secret Computation

class Curve:

    def __init__(self, a, p):
        self.a = a
        self.p = p

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P

        (x1, y1) = P
        (x2, y2) = Q

        if x1 == x2 and (y1 + y2) % self.p == 0:  # because of the group in which we are working Fp
            return None

        if P != Q:
            num = (y2 - y1) % self.p
            den = (x2 - x1) % self.p
        else:
            num = (3 * pow(x1, 2) + self.a) % self.p
            den = 2 * y1 % self.p

        lbd = num * pow(den, -1, self.p) % self.p
        x3 = (pow(lbd, 2) - x1 - x2) % self.p
        y3 = (lbd * (x1 - x3) - y1) % self.p

        return (x3, y3)

    def scalar_mul(self, P, n):
        Q = P
        R = None

        while n > 0:
            if n % 2 == 1:
                R = self.add(R, Q)

            Q = self.add(Q, Q)
            n = n // 2
        return R

    def compute_SharedSecret(self, PubKey, PrivKey):
        try:
            shared_secret = self.scalar_mul(PubKey, PrivKey)
        except ValueError:
            print('[X] Error')

        return shared_secret















