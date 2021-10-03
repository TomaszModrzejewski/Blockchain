"""
Benchmarking of ecdsa functions
"""

import os
import time

from ecdsa import (
    gen_key_pair,
    sign,
    verify,
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

        print("1.000 times %s() took %.2fs" % (r.__name__, t2 - t1))

    return timer_fn


@timer
def benchmark_sign(sk, msgs):

    """
    Benchmark sign function
    """

    for msg in msgs:
        assert sign(msg, sk)

    return sign


@timer
def benchmark_verify(vk, sigs, msgs):

    """
    Benchmark verify function
    """

    for e in range(len(sigs)):
        assert verify(msgs[e], sigs[e], vk)

    return verify


def main():

    """
    Execute all the benchmarks
    """

    sk, vk = gen_key_pair()

    msgs = [os.urandom(16) for _ in range(1000)]
    sigs = [sign(msg, sk) for msg in msgs]

    benchmark_sign(sk, msgs)
    benchmark_verify(vk, sigs, msgs)


if __name__ == '__main__':
    main()
