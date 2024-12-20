import random
from math import sqrt, ceil

class PrimeUtils:
    @classmethod
    def miller_test(cls, t, n):
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

    @classmethod
    def is_prime(cls, n, k):
        if n <= 1 or n == 4:
            return False
        if n <= 3:
            return True

        t = n - 1
        while t % 2 == 0:
            t //= 2

        for _ in range(k):
            if not cls.miller_test(t, n):
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
            while p % 2 == 0 and not cls.is_prime(p, prime_trial_count):
                p = random.randint(min_value + 1, max_value)
            return p


class MessageConverter:
    def __init__(self, chars: str):
        self.chars = {}
        self.char_vals = {}

        for i in range(0, len(chars)):
            self.chars[chars[i]] = i + 1
            self.char_vals[i + 1] = chars[i]

        self.length = len(chars) + 1

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

        if message_num == 0:
            return "_"  # Return "_" if message is 0

        while message_num > 0:
            char_index = message_num % self.length
            message_num //= self.length
            result = self.char_vals[char_index] + result

        return result

    def split_string_into_chunks(self, string: str, size: int):
        # Split the string into chunks
        chunks = [string[i:i + size] for i in range(0, len(string), size)]

        return chunks

    def remove_padding(self, message: str) -> str:
        return message.rstrip # Remove trailing padding of spaces


class ElGamalEncryption:
    def __init__(self, plaintext_block_length, alphabet):
        self.plaintext_block_length = plaintext_block_length
        self.message_converter = MessageConverter(alphabet)

    def generate_keys(self):
        p = PrimeUtils.generate_prime_interval(
            (self.message_converter.length - 1) ** self.plaintext_block_length + 1,
            (self.message_converter.length - 1) ** (self.plaintext_block_length + 1), 4
        )

        g = PrimeUtils.find_generator(p)
        a = random.randint(1, p - 2)

        return (p, g, pow(g, a, p)), a

    def encrypt(self, key, message):
        chunks = self.message_converter.split_string_into_chunks(message, self.plaintext_block_length)

        p, g, ga = key
        ciphertext_chunks = []

        for chunk in chunks:
            converted_message = self.message_converter.to_num(chunk)
            k = random.randint(1, p)
            alpha = pow(g, k, p)
            beta = converted_message * pow(ga, k, p) % p
            ciphertext_chunks.append((alpha, beta))

        return ciphertext_chunks

    def decrypt(self, key, ciphertext_chunks):
        public, a = key
        p, g, ga = public

        plaintext_chunks = []
        for alpha, beta in ciphertext_chunks:
            m = pow(alpha, -a, p) * beta % p
            plaintext_chunks.append(self.message_converter.to_str(m))

        # Join the chunks
        decrypted_message = "".join(plaintext_chunks)
        return decrypted_message 

if __name__ == "__main__":
    encrypter = ElGamalEncryption(3, " abcdefghijklmnopqrstuvwxyz")
    message = "  the quick brown fox jumps over the lazy dog  "
    print(f" Original message: |{message}|")
    
    keys = encrypter.generate_keys()

    encrypted_message = encrypter.encrypt(keys[0], message)
    print(f"Encrypted message: {encrypted_message}")

    decrypted_message = encrypter.decrypt(keys, encrypted_message)
    print(f"Decrypted message: |{decrypted_message}|")
    print(f"Decrypted message is the same as original: {message == decrypted_message}")
