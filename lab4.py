import random
from math import sqrt, ceil

# lab4 - ex. 3
# lab5 - ex. 5

def prime_factors(n):
    factors = []

    while n % 2 == 0:
        factors.append(2)
        n //= 2
    
    for i in range(3, ceil(sqrt(n)), 2):
        while n % i == 0:
            factors.append(i)
            n //= i
    
    # if n is a prime number
    if n > 2:
        factors.append(n)
    
    return factors

def find_generator(p):
    phi = p - 1
    factors = prime_factors(phi)

    # Test candidates for g
    for g in range(2, p):
        is_generator = True
        for q in factors:
            # Check if g^(phi/q) =/= 1 (mod p)
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

# Miller-Rabin test
def isPrime(n, k):
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True

    t = n - 1
    while t % 2 == 0:
        t //= 2

    for _ in range(k):
        if not MillerTest(t, n):
            return False

    return True

# good for 4 letter words
def generate_prime_hardcoded():
    return 923501

def generate_prime_bits(bits, prime_trial_count):
    while(1):
        p = random.randint( 2**(bits-1), 2**(bits) - 1 )

        while(p % 2 != 0 and not isPrime(p, prime_trial_count)):
            p = random.randint( 2**(bits-1), 2**(bits) - 1 )

        return p
                      
def generate_prime_interval(min_value, max_value, prime_trial_count):
    while(1):
        p = random.randint( min_value + 1, max_value )

        while(p % 2 != 0 and not isPrime(p, prime_trial_count)):
            p = random.randint( min_value + 1, max_value )

        return p
    
def generate_keys(min_size_power):
    p = generate_prime_interval(27 ** min_size_power, 27 ** (min_size_power + 1), 4)
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

    # TODO: figure out why alpha is sometimes invertible (the program crashes 🙃)
    m = pow(alpha, -a, p) * beta % p
    
    return message_to_str(m)

message = "hello"
keys = generate_keys(len(message))
encrypted = encrypt(keys[0], message)
print(decrypt(keys, encrypted))