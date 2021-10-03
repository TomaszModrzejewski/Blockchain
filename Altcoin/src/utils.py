from config import (
    TEN_MINUTES,
    MAX_TARGET
)


def int_to_little_endian(nb, size):

    """
    Integer to little endian
    """

    return nb.to_bytes(size, 'little')


def little_endian_to_int(b):

    """
    Little endian to integer
    """

    return int.from_bytes(b, 'little')


def int_to_varint(i):

    """
    Integer to variable integer
    """

    if i < 0xfd:
        return bytes([i])

    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)

    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i, 4)

    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8)


def varint_to_int(s):

    """
    Variable integer to integer
    """

    i = s.read(1)[0]

    if i == 0xfd:
        return little_endian_to_int(s.read(2))

    elif i == 0xfe:
        return little_endian_to_int(s.read(4))

    elif i == 0xff:
        return little_endian_to_int(s.read(8))

    else:
        return i


def target_to_bits(target):

    """
    Mining target to bits
    """

    b = target.to_bytes(32, 'big')
    b = b.lstrip(b'\x00')

    if b[0] >= 0x7f:

        coeff = b'\x00' + b[:2]
        exp = len(b) + 1

    else:
        coeff, exp = b[:3], len(b)

    return coeff[::-1] + bytes([exp])


def bits_to_target(bits):

    """
    Bits to mining target
    """

    coeff = little_endian_to_int(bits[:-1])
    return coeff * 256 ** (bits[-1] - 3)


def calculate_new_bits(prev_bits, dt):

    """
    Compute new block mining target
    """

    dt = max(min(dt, TEN_MINUTES * 4), TEN_MINUTES // 4)

    prev_target = bits_to_target(prev_bits)
    target = prev_target * dt / TEN_MINUTES

    return target_to_bits(min(int(target), MAX_TARGET))


if __name__ == '__main__':
    pass
