from op import (
    OP_CODE_FUNCTIONS,
    OP_CODE_NAMES,
)
from utils import (
    int_to_little_endian,
    int_to_varint,
    little_endian_to_int,
    varint_to_int,
)


class Script:

    """
    Python class for scripts
    """

    def __init__(self, cmds=None):

        if not cmds:
            self.cmds = []
        else:
            self.cmds = cmds

    def evaluate(self, z):

        """
        Execute and evaluate script
        """

        cmds = self.cmds[:]
        stack = []

        while len(cmds) > 0:

            cmd = cmds.pop(0)

            if isinstance(cmd, int):

                operation = OP_CODE_FUNCTIONS[cmd]

                if cmd in [0x09, 0x0A]:
                    if not operation(stack, z):
                        return False

                else:
                    if not operation(stack):
                        return False

            else:
                stack.append(cmd)

        if len(stack) != 1:
            return False

        if stack[0] == b'':
            return False

        return stack[0] == 1

    def encode(self):

        """
        Encoding script to bytes
        """

        result = bytes()

        for cmd in self.cmds:

            if isinstance(cmd, int):
                result += int_to_little_endian(cmd, 1)

            else:

                length = int_to_little_endian(len(cmd), 1)
                result += b'\x00' + length + cmd

        total = int_to_varint(len(result))

        return total + result

    @classmethod
    def decode(cls, s):

        """
        Decoding bytes encoded script
        """

        total = varint_to_int(s)
        cmds = []

        count = 0

        while count < total:

            current = s.read(1)[0]
            count += 1

            if current == 0x00:

                length = little_endian_to_int(s.read(1))
                cmds.append(s.read(length))
                count += length + 1

            else:

                cmds.append(current)

        return cls(cmds)

    def __add__(self, other):

        """
        Concatenate to an other script
        """

        return Script(self.cmds + other.cmds)

    def __repr__(self):

        """
        String representation of this script
        """

        result = []

        for cmd in self.cmds:

            if type(cmd) == int:

                name = OP_CODE_NAMES.get(cmd)
                result.append(name)

            else:
                result.append(cmd.hex())

        return ' '.join(result)


if __name__ == '__main__':
    pass
