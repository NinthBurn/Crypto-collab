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
    
    def accepts_input(self, input: str) -> bool:
        for char in input:
            if char not in self.char_vals.values():
                raise ValueError("Provided string contains characters not defined in the alphabet")


class ElGamalEncryption:
    def __init__(self, plaintext_block_length, alphabet):
        self.plaintext_block_length = plaintext_block_length
        self.message_converter = MessageConverter(alphabet)

    def generate_keys(self):
        p = PrimeUtils.generate_prime_interval(
            (self.message_converter.length) ** self.plaintext_block_length + 1,
            (self.message_converter.length) ** (self.plaintext_block_length + 1), 4
        )

        g = PrimeUtils.find_generator(p)
        a = random.randint(1, p - 2)

        return (p, g, pow(g, a, p)), a

    def validateInput(self, message: str) -> str:
        self.message_converter.accepts_input(message)

        if len(message) % self.plaintext_block_length != 0:
            correct_size = len(message) + (self.plaintext_block_length - len(message) % self.plaintext_block_length)
            print(f"Input message cannot be evenly split into chunks -> it will be modified by adding blanks to the right")
            return message.ljust(correct_size, self.message_converter.first_char)
        
        return message

    def encrypt(self, key, message):
        chunks = self.message_converter.split_string_into_chunks(message, self.plaintext_block_length)

        p, g, ga = key
        ciphertext_chunks: list[(int, int)] = []

        for chunk in chunks:
            converted_message = self.message_converter.to_num(chunk)
            k = random.randint(1, p)
            alpha = pow(g, k, p)
            beta = converted_message * pow(ga, k, p) % p
            ciphertext_chunks.append((alpha, beta))

        encrypted_message = ""

        for chunk in ciphertext_chunks:
            # alpha + beta to string (padded)
            padded_size = self.plaintext_block_length + 1
            encrypted_message += self.message_converter.to_str_padded(chunk[0], padded_size) 
            encrypted_message += self.message_converter.to_str_padded(chunk[1], padded_size)

        return encrypted_message, ciphertext_chunks

    def decrypt(self, key, encrypted_message):
        public, a = key
        p, g, ga = public

        plaintext_chunks = []
        ciphertext_chunks = self.message_converter.split_string_into_chunks(encrypted_message[0], self.plaintext_block_length + 1)

        for i in range(0, len(ciphertext_chunks) - 1, 2):
            alpha = self.message_converter.to_num(ciphertext_chunks[i])
            beta = self.message_converter.to_num(ciphertext_chunks[i + 1])
            m = pow(alpha, -a, p) * beta % p
            
            converted_message = self.message_converter.to_str_padded(m, self.plaintext_block_length)
            plaintext_chunks.append(converted_message)

        # Join the chunks
        decrypted_message = "".join(plaintext_chunks)
        return decrypted_message 

if __name__ == "__main__":
    encrypter = ElGamalEncryption(3, " abcdefghijklmnopqrstuvwxyz")
    message = "  the quick brown fox jumps over the lazy dog  "
    message = encrypter.validateInput(message)
    print(f" Original message: |{message}|")
    
    keys = encrypter.generate_keys()

    encrypted_message = encrypter.encrypt(keys[0], message)
    print(f"Encrypted message string: {encrypted_message[0]}")
    print(f"Encrypted message value: {encrypted_message[1]}")

    decrypted_message = encrypter.decrypt(keys, encrypted_message)
    print(f"Decrypted message: |{decrypted_message}|")

    print(f"Decrypted message is the same as original: {message == decrypted_message}")
