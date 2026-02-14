##https://cryptohack.org/courses/elliptic/ecc1/
## https://cryptohack.org/courses/elliptic/ecc2/
## ****
## https://cryptohack.org/courses/elliptic/ecc3/
## Point addition
## Scalar Multiplication
## Share Secret Computation
## Mongomery curve
from sympy.ntheory import sqrt_mod

class Curve:
    def __init__(self, a, p, b):
        self.a = a
        self.p = p
        self.b = b

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

    def compute_y_from_x(self, x): ## works only if x is the coordinate of a point on the curve
        y_2 = (x**3 + self.a*x + self.b) % self.p
        y = sqrt_mod(y_2, self.p) ## tonelli shanks for squarred root moduli
        return y

class MongomeryCurve:
    def __init__(self, A, B, p):
        self.A = A
        self.B = B
        self.p = p

    def mong_add(self, P, Q):
        if P is None: return Q
        if Q is None: return P
        if P == Q: return self.mong_double(P)
        
        x1, y1 = P
        x2, y2 = Q
        num = (y2 - y1) % self.p
        den = (x2 - x1) % self.p
        alpha = (num * pow(den, -1, self.p)) % self.p
        x3 = (self.B * pow(alpha, 2) - self.A - x1 - x2) % self.p
        y3 = (alpha * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def mong_double(self, P):
        if P is None: return None
        x1, y1 = P
        num = (3 * pow(x1, 2) + 2 * self.A * x1 + 1) % self.p
        den = (2 * self.B * y1) % self.p
        alpha = (num * pow(den, -1, self.p)) % self.p
        x3 = (self.B * pow(alpha, 2) - self.A - 2 * x1) % self.p
        y3 = (alpha * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def mong_scalar_mul(self, P, k):
        n = k.bit_length()
        if n == 0: return None
        
        # Init
        R0 = P
        R1 = self.mong_double(P)
        
        i = n - 2
        while i >= 0:
            k_i = (k >> i) & 1
            if k_i == 0:
                R1 = self.mong_add(R0, R1)
                R0 = self.mong_double(R0)    
            else:
                R0 = self.mong_add(R0, R1)
                R1 = self.mong_double(R1)
            i -= 1
        return R0

    def compute_y_from_x_montgomery(self, x):
    #B = 1
        y_2 = (pow(x, 3, self.p) + self.A * pow(x, 2, self.p) + x) % self.p
        y = sqrt_mod(y_2, self.p)
        return int(y)












