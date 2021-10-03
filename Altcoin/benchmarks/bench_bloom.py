"""
Benchmarking of bloom filters
"""

import os
import time

from bloom import (
    BloomFilter
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
        func(*args, **kwargs)
        t2 = time.time()

        print("100.000 times %s() took %.2fs" % (func.__name__, t2 - t1))

    return timer_fn


@timer
def benchmark_add(bloom_filter, elements):

    """
    Benchmark bloom filter add function
    """

    for e in elements:
        bloom_filter.add(e)


@timer
def benchmark_has(bloom_filter, elements):

    """
    Benchmark bloom filter has function
    """

    for e in elements:
        assert bloom_filter.has(e)


def main():

    """
    Execute all the benchmarks
    """

    n = 100000

    bf = BloomFilter(n, 1e-9)
    elements = [os.urandom(16) for _ in range(n)]

    benchmark_add(bf, elements)
    benchmark_has(bf, elements)


if __name__ == '__main__':
    main()
