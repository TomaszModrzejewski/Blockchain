import hashlib


def keccak256(s):

    """
    Keccak256 hash function
    """

    return hashlib.sha3_256(s).digest()


def hash160(s):

    """
    Ripemd160 hash of sha256 hash function
    """

    return hashlib.new('ripemd160', sha256(s)).digest()


def hash256(s):

    """
    Double sha256 hash function
    """

    return sha256(sha256(s))


def sha256(s):

    """
    Sha256 hash function
    """

    return hashlib.sha256(s).digest()


if __name__ == '__main__':
    pass
