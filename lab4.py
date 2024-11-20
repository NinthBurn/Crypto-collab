

# lab4 - ex. 3
# lab5 - ex. 5

import random

def prime_factors(p):
    result = []
    for d in range(2, (p) + 1):
        if p % d == 0:
            result.append(d)

    return result

def find_generator(p):
    # Factorize p-1
    phi = p - 1
    factors = prime_factors(phi)

    # Test candidates for g
    for g in range(2, p):
        is_generator = True
        for q in factors:
            # Check if g^(phi/q) ≠ 1 (mod p)
            if pow(g, phi // q, p) == 1:
                is_generator = False
                break

        if is_generator:
            return g
        
def MillerTest(t, n):
    a = 2 + random.randint(1, n - 4)

    x = pow(a, t, n)

    if x == 1 or x == n - 1:
        return True

    while t != n - 1:
        x = (x * x) % n
        t *= 2

        if x == 1:
            return False
        if x == n - 1:
            return True

    return False


# It returns false if n is composite and returns true if n is probably prime
# k is an input parameter that determines the number of iterations
# Miller-Rabin test
def isPrime(n, k):
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True

    t = n - 1
    while t % 2 == 0:
        t //= 2

    for i in range(k):
        if not MillerTest(t, n):
            return False

    return True

def find_prime(iNumBits, iConfidence):
    while(1):
        p = random.randint( 2**(iNumBits-1), 2**(iNumBits) - 1 )

        while( p % 2 == 0 ):
            p = random.randint( 2**(iNumBits-1), 2**(iNumBits) - 1 )
        
        while(not isPrime(p, iConfidence)):
            p = random.randint( 2**(iNumBits-1), 2**(iNumBits) - 1 )
            while( p % 2 == 0):
                p = random.randint( 2**(iNumBits-1), 2**(iNumBits) - 1 )

        return p

def find_prime(iNumBits, iConfidence):
	while(1):
		#generate potential prime randomly
		p = random.randint( 2**(iNumBits-1), 2**(iNumBits) - 1 )
		
		while( p % 2 == 0 ):
			p = random.randint( 2**(iNumBits-1), 2**(iNumBits) - 1 )

		while( not isPrime(p, iConfidence) ):
			p = random.randint( 2**(iNumBits-1), 2**(iNumBits) - 1 )
			while( p % 2 == 0 ):
			    p = random.randint( 2**(iNumBits-1), 2**(iNumBits) - 1 )
                      
def generate_keys(keyBitsLength):
    # p = find_prime(keyBitsLength, 4)
    p = 6999213259363483493573619703 
    p = 27355171113117131161195233 
    g = find_generator(p)

    a = random.randint(1, p - 2)

    return ((p, g, pow(g, a, p)), a)

chars = {' ': 0}
for i in range(ord('a'), ord('z') + 1):
    chars[chr(i)] = i - 96

def encrypt(key, message):
    length = len(message)

    converted_message = chars[message[length - 1]]
    pos = 27

    for index in range(length - 2, -1, -1):
        converted_message += pos * chars[message[index]]
        pos *= 27
         
    p, g, ga = key

    k = random.randint(1, p)
    alpha = pow(g, k, p)
    beta = converted_message * pow(ga, k, p)

    ciphertext = (alpha, beta)

    return ciphertext

def message_to_str(num):
    result = ""

    while(num > 0):
        r = num % 27
        num //= 27

        if r == 0:
            result = " " + result
        else: result = chr(r + 96) + result         

    return result

def decrypt(key, ciphertext):
    public, a = key
    p, g, ga = public
    alpha, beta = ciphertext

    m = pow(alpha, -a, p) * beta % p
    
    return message_to_str(m)


keys = generate_keys(8)
encrypted = encrypt(keys[0], "hello")
print(decrypt(keys, encrypted))