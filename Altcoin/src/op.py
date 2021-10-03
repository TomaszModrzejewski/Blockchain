"""
TODO: Multi signature check
"""

import time

from ecdsa import verify
from hash import hash256, hash160


def op_nop(stack):

    """
    True if element in the stack
    """

    return len(stack) >= 0


def op_return(stack):

    """
    Opposite of op_nop
    """

    return not op_nop(stack)


def op_dup(stack):

    """
    Duplicate an element of the stack
    """

    if len(stack) < 1:
        return False

    stack.append(stack[-1])
    return True


def op_drop(stack):

    """
    Delete last element of the stack
    """

    if len(stack) < 1:
        return False

    stack.pop()

    return True


def op_verify(stack):

    """
    Verify stack last element
    """

    if len(stack) < 1:
        return False

    if stack.pop() == 0:
        return False

    return True


def op_equal(stack):

    """
    Equality of stack last 2 elements
    """

    if len(stack) < 2:
        return False

    element1 = stack.pop()
    element2 = stack.pop()

    if element1 == element2:
        stack.append(0x01)
    else:
        stack.append(0x00)

    return True


def op_equalverify(stack):

    """
    Do both Verify & Equality checks
    """

    return op_equal(stack) and op_verify(stack)


def op_hash160(stack):

    """
    Hash160 of last element
    """

    if len(stack) < 1:
        return False

    element = stack.pop()
    stack.append(hash160(element))

    return True


def op_hash256(stack):

    """
    Hash256 of last element
    """

    if len(stack) < 1:
        return False

    element = stack.pop()
    stack.append(hash256(element))

    return True


def op_checksig(stack, z):

    """
    Check signature
    """

    if len(stack) < 2:
        return False

    sec = stack.pop()
    der = stack.pop()[:-1]

    if verify(z, der, sec):
        stack.append(0x01)
    else:
        stack.append(0x00)

    return True


def op_checkmultisig(stack, z):

    """
    Check multiple signatures
    """

    if len(stack) < 1:
        return False

    assert z  # Next ...

    return True


def op_checklocktimeverify(stack):

    """
    Check and verify locktime
    """

    if len(stack) < 1:
        return False

    element = stack[-1]

    if element < 0:
        return False

    if element > 500000000:
        return False

    if element < int(time.time()):
        return False

    return True


OP_CODE_FUNCTIONS = {
    0x01: op_nop,
    0x02: op_verify,
    0x03: op_return,
    0x04: op_dup,
    0x05: op_equal,
    0x06: op_equalverify,
    0x07: op_hash160,
    0x08: op_hash256,
    0x09: op_checksig,
    0x0A: op_checkmultisig,
    0x0B: op_drop,
    0x0C: op_checklocktimeverify,
}


OP_CODE_NAMES = {
    0x01: 'OP_NOP',
    0x02: 'OP_VERIFY',
    0x03: 'OP_RETURN',
    0x04: 'OP_DUP',
    0x05: 'OP_EQUAL',
    0x06: 'OP_EQUALVERIFY',
    0x07: 'OP_HASH160',
    0x08: 'OP_HASH256',
    0x09: 'OP_CHECKSIG',
    0x0A: 'OP_CHECKMULTISIG',
    0x0B: 'OP_DROP',
    0x0C: 'OP_CHECKLOCKTIMEVERIFY',
}

if __name__ == '__main__':
    pass
