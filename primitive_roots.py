from fractions import gcd
import random 

# Computes Euler's totient for n.    
def phi(n):
    b=n-1
    c=0
    while b:
        if not gcd(n,b)-1:
            c+=1
        b-=1
    return c

# Computes the factorization of n.
def find_prime_factors(n):
    i = 2
    factors = []
    while i * i <= n:
        if n % i:
            i += 1
        else:
            n //= i
            factors.append(i)
    if n > 1:
        factors.append(n)
    return factors

# Computes the primitive roots of n.
def primitive_roots(n):
    prim_roots = []
    phi_n = phi(n)
    prime_factors = find_prime_factors(phi_n)
    k = len(prime_factors)
    for i in range(1,n):
        found = True
        for j in range(1,k):
            ai = pow(i, phi_n/prime_factors[j],n)
            if ai == 1:
                found = False
                break
        if found:
            prim_roots.append(i)
    return prim_roots

# main _ test
if __name__ == "__main__":
    p = 17
    print (phi(p))
    print(primitive_roots(p))