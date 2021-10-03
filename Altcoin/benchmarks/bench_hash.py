"""
Benchmarking of hash functions
"""

import os
import time

from hash import (
    keccak256,
    hash160,
    hash256,
    sha256
)


def timer(func):

    """
    Timer decorator
    """

    def timer_fn(*args, **kwargs):

        """
        Nested function for timing other functions
        """

        t1 = time.time()
        r = func(*args, **kwargs)
        t2 = time.time()

        print("100.000 times %s() took %.2fs" % (r.__name__, t2 - t1))

    return timer_fn


@timer
def benchmark_keccak256():

    """
    Benchmark keccak256 hash function
    """

    for e in range(100000):
        keccak256(os.urandom(16))

    return keccak256


@timer
def benchmark_hash160():

    """
    Benchmark hash160 hash function
    """

    for e in range(100000):
        hash160(os.urandom(16))

    return hash160


@timer
def benchmark_hash256():

    """
    Benchmark hash256 hash function
    """

    for e in range(100000):
        hash256(os.urandom(16))

    return hash256


@timer
def benchmark_sha256():

    """
    Benchmark sha256 hash function
    """

    for e in range(100000):
        sha256(os.urandom(16))

    return sha256


def main():

    """
    Execute all the benchmarks
    """

    benchmark_keccak256()
    benchmark_hash160()
    benchmark_hash256()
    benchmark_sha256()


if __name__ == '__main__':
    main()
