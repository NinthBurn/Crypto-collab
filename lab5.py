import random
from math import sqrt, ceil
from functools import reduce
import sympy

class PrimeUtils:
    @classmethod
    def is_prime(cls, n, k): 
        for i in range(2, n):
            if n % i == 0:
                return False
        return True
    
    @classmethod
    def prime_factors(cls, n):
        factors = []
        while n % 2 == 0:
            factors.append(2)
            n //= 2

        for i in range(3, ceil(sqrt(n)), 2):
            while n % i == 0:
                factors.append(i)
                n //= i

        if n > 2:
            factors.append(n)

        return factors

    @classmethod
    def find_generator(cls, p):
        phi = p - 1
        factors = cls.prime_factors(phi)

        for g in range(2, p):
            is_generator = True
            for q in factors:
                if pow(g, phi // q, p) == 1:
                    is_generator = False
                    break

            if is_generator:
                return g

    @classmethod
    def jacobi(cls, a, n):
        if a == 0:
            return 0
        if a == 1:
            return 1

        e = 0
        a1 = a
        while a1 % 2 == 0:
            e += 1
            a1 = a1 // 2
        assert 2**e * a1 == a

        s = 0

        if e % 2 == 0:
            s = 1
        elif n % 8 in {1, 7}:
            s = 1
        elif n % 8 in {3, 5}:
            s = -1

        if n % 4 == 3 and a1 % 4 == 3:
            s *= -1

        n1 = n % a1
        
        if a1 == 1:
            return s
        else:
            return s * cls.jacobi(n1, a1)

    @classmethod
    def quadratic_non_residue(cls, p):
        a = 0
        while cls.jacobi(a, p) != -1:
            a = random.randint(1, p)

        return a
    
    '''
    Returns gcd(a,b), x and y, where gcd(a,b) = ax + by
    '''
    @classmethod
    def gcd_extended(cls, a, b):
        x = [1, 0]
        y = [0, 1]
        sign = 1
    
        while b:
            q, r = divmod(a, b)
            a, b = b, r
            x[1], x[0] = q*x[1] + x[0], x[1]
            y[1], y[0] = q*y[1] + y[0], y[1]
            sign = -sign
    
        x = sign * x[0]
        y = -sign * y[0]

        return a, x, y

    '''
    Chinese Remainder theorem
    Returns x, where x = a % m
    '''
    @classmethod
    def gauss_crt(cls, a, m):
        modulus = reduce(lambda a,b: a*b, m)
    
        multipliers = []
        for m_i in m:
            M = modulus // m_i
            gcd, inverse, y = cls.gcd_extended(M, m_i)
            multipliers.append(inverse * M % modulus)
    
        result = 0
        for multi, a_i in zip(multipliers, a):
            result = (result + multi * a_i) % modulus

        return result
    
    @classmethod
    def pseudosquare(cls, p, q):
        a = cls.quadratic_non_residue(p)
        b = cls.quadratic_non_residue(q)
        return cls.gauss_crt([a, b], [p, q])
    
    @classmethod
    def generate_prime_bits(cls, bits, prime_trial_count):
        while True:
            p = random.randint(2 ** (bits - 1) + 1, 2 ** (bits) - 1)
            while p % 2 == 0 and not cls.is_prime(p, prime_trial_count):
                p = random.randint(2 ** (bits - 1) + 1, 2 ** (bits) - 1)
            return p

    @classmethod
    def generate_prime_interval(cls, min_value, max_value, prime_trial_count):
        while True:
            p = random.randint(min_value + 1, max_value)
            while not cls.is_prime(p, prime_trial_count):
                p = random.randint(min_value + 1, max_value)
            return p


class MessageConverter:
    def __init__(self, chars: str):
        self.chars = {}
        self.char_vals = {}

        for i in range(0, len(chars)):
            self.chars[chars[i]] = i
            self.char_vals[i] = chars[i]

        self.first_char = self.char_vals[0]
        self.length = len(chars)

    def to_num(self, message_string: str) -> int:
        str_len = len(message_string)
        converted_message = self.chars[message_string[str_len - 1]]
        current_pos = self.length

        for index in range(str_len - 2, -1, -1):
            converted_message += current_pos * self.chars[message_string[index]]
            current_pos *= self.length

        return converted_message

    def to_str(self, message_num: int) -> str:
        result = ""

        while message_num > 0:
            char_index = message_num % self.length
            message_num //= self.length
            result = self.char_vals[char_index] + result

        return result
    
    def to_str_padded(self, message_num: int, padding_size: int) -> str:
        result = ""

        while message_num > 0:
            char_index = message_num % self.length
            message_num //= self.length
            result = self.char_vals[char_index] + result

        return result.rjust(padding_size, self.first_char)

    def split_string_into_chunks(self, string: str, size: int) -> list[str]:
        chunks = [string[i:i + size] for i in range(0, len(string), size)]

        return chunks

    def remove_padding(self, message: str) -> str:
        return message.rstrip()
    
    # each character is represented by 5 bits
    def to_binary(self, message):
        return ''.join(f'{self.chars[char]:05b}' for char in message)

    def from_binary(self, binary_str):
        chars = [self.char_vals[int(binary_str[i:i+5], 2)] for i in range(0, len(binary_str), 5)]
        return ''.join(chars)

    def accepts_input(self, input: str) -> bool:
        for char in input:
            if char not in self.char_vals.values():
                raise ValueError("Provided string contains characters not defined in the alphabet")


class GoldwasserMicaliEncryption:
    def __init__(self, plaintext_block_length, alphabet):
        self.plaintext_block_length = plaintext_block_length
        self.message_converter = MessageConverter(alphabet)

    def generate_keys(self):
        p = PrimeUtils.generate_prime_interval(
            (self.message_converter.length) ** (self.plaintext_block_length) + 1,
            (self.message_converter.length) ** (self.plaintext_block_length + 1), 10
        )

        q = p

        while p == q:
            q = PrimeUtils.generate_prime_interval(
            (self.message_converter.length) ** (self.plaintext_block_length) + 1,
            (self.message_converter.length) ** (self.plaintext_block_length + 1), 10
            )

        y = PrimeUtils.pseudosquare(p, q)
        n = p * q

        return (n, y), (p, q)

    def validateInput(self, message: str) -> str:
        self.message_converter.accepts_input(message)

        return message
 
    """Take string and return the concatenated ASCII codes as an integer."""
    @classmethod
    def encode(cls, input_string: str):
        return int(''.join(("%03d" % char) for char in input_string.encode('ascii', 'ignore')))

    """Encrypt the message and return the ciphertext."""
    def encrypt(self, public_key, message):
        # Convert the message to binary representation
        binary_message = [bit == "1" for bit in "{0:b}".format(GoldwasserMicaliEncryption.encode(message))]
        
        modulus, encryption_key = public_key

        def encrypt_bit(binary_bit):
            random_number = random.randint(0, modulus)
            if binary_bit:
                return (encryption_key * pow(random_number, 2, modulus)) % modulus
            return pow(random_number, 2, modulus)

        # Encrypt all bits of the message
        return list(map(encrypt_bit, binary_message))

    """Take ASCII codestring and return the original string."""
    @classmethod
    def decode(cls, encoded_ascii_codestring):
        ascii_code_string = str(encoded_ascii_codestring)
        total_length, chunk_size = len(ascii_code_string), 3
        
        # Handle cases where the length isn't a multiple of 3
        if total_length % 3 == 1:
            ascii_code_string = "00" + ascii_code_string
        elif total_length % 3 == 2:
            ascii_code_string = "0" + ascii_code_string
            total_length += 1

        # Split the string into chunks of 3 characters
        ascii_chunks = [ascii_code_string[total_length - i - chunk_size: total_length - i] for i in range(0, total_length, chunk_size)]
        
        # Convert each chunk back to a character
        decoded_message = ""
        for ascii_chunk in ascii_chunks:
            decoded_char = chr(int(ascii_chunk))
            decoded_message = decoded_char + decoded_message
        
        return decoded_message

    """Decrypt the ciphertext and return the original message."""
    def decrypt(self, private_key, ciphertext):
        p, q = private_key

        def decrypt_bit(encrypted_bit):
            """Return False if bit is a quadratic residue, True otherwise."""
            jacobi_symbol = PrimeUtils.jacobi(encrypted_bit, p)
            if jacobi_symbol == 1:
                return False
            return True

        # Decrypt all bits of the ciphertext
        decrypted_bits = list(map(decrypt_bit, ciphertext))
        
        binary_string = ''.join(['1' if bit else '0' for bit in decrypted_bits])
        
        return self.decode(int(binary_string, 2))
    
if __name__ == "__main__":
    encrypter = GoldwasserMicaliEncryption(3, " abcdefghijklmnopqrstuvwxyz")
    message = "  the quick brown fox jumps over the lazy dog  "
    encrypter.validateInput(message)
    print(f" Original message: |{message}|")
    
    keys = encrypter.generate_keys()

    print(f"Keys: {keys}")
    encrypted_message = encrypter.encrypt(keys[0], message)
    #print(f"Encrypted message string: {encrypted_message}")

    decrypted_message = encrypter.decrypt(keys[1], encrypted_message)
    print(f"Decrypted message: |{decrypted_message}|")

    print(f"Decrypted message is the same as original: {message == decrypted_message}")
