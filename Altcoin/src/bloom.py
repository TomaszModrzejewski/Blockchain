import math

import bitarray
import mmh3


class BloomFilter:

    """
    Python class for bloom filters
    """

    def __init__(self, n, p):

        """
        Bloom filter initialisation
        """

        self.m = math.ceil(-n * math.log2(p) / math.log(2))
        self.k = math.ceil(-math.log2(p))

        self.bits = bitarray.bitarray(self.m)
        self.bits.setall(0)

    def get_indices(self, e):

        """
        Compute murmur3 indices
        """

        hash_0 = mmh3.hash(e, 0)
        hash_1 = mmh3.hash(e, 1)

        return (
            (hash_0 + i*hash_1) % len(self.bits)
            for i in range(1, self.k + 1)
        )

    def add(self, e):

        """
        Adding element to filter
        """

        for index in self.get_indices(e):
            self.bits[index] = 1

    def has(self, e):

        """
        Is element in filter ?
        """

        for index in self.get_indices(e):
            if self.bits[index] == 0:
                return False

        return True

    def save(self):

        """
        Encode filter to bytes
        """

        return self.bits.tobytes()

    def load(self, b):

        """
        Load bytes encoded filter
        """

        self.bits.frombytes(b)


if __name__ == '__main__':
    pass
