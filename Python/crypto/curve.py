##https://cryptohack.org/courses/elliptic/ecc1/
## Point addition

class Curve:
    def __init__(self, a, p):
        self.a = a  
        self.p = p 

    def add(self, P, Q):
        if P is None: return Q
        if Q is None: return P
        
        x1, y1 = P
        x2, y2 = Q

        if x1 == x2 and (y1 + y2) % self.p == 0 : # because of the group in which we are working Fp
            return None
	
	# compute lambda
        if P != Q:
            num = (y2 - y1) % self.p
            den = (x2 - x1) % self.p
        else:
            num = (3 * pow(x1, 2) + self.a) % self.p
            den = (2 * y1) % self.p

        lbd = (num * pow(den, -1, self.p)) % self.p
        x3 = (pow(lbd, 2) - x1 - x2) % self.p
        y3 = (lbd * (x1 - x3) - y1) % self.p
        
        return (x3, y3)

P=(493,5564)
Q=(1539,4742)
R=(4403,5202)

#P + P + Q +R
C = Curve(a=497, p=9739)
temp = C.add(P,P)
temp = C.add(temp,Q)
res = C.add(temp,R)
print(res)

X = (5274,2841)
Y=(8669,740)
print(C.add(X,Y))
print(C.add(X,X))
