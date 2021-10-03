from dataclasses import dataclass

from script import Script
from utils import (
    int_to_little_endian,
    little_endian_to_int
)


@dataclass
class UTXO:

    """

    Python class for UTXOs

    """

    tx_hash: bytes
    output_index: int
    script_pubkey: Script
    output_value: int

    def encode(self):

        """ Encode UTXO to bytes """

        return bytes(
            self.tx_hash[::-1] +
            int_to_little_endian(self.output_index, 4) +
            self.script_pubkey[::-1] +
            int_to_little_endian(self.output_value, 4)
        )

    @classmethod
    def decode(cls, s):

        """ Decode bytes to UTXO """

        return cls(
            s.read(32),
            little_endian_to_int(s.read(4)),
            s.read(32),
            little_endian_to_int(s.read(4)),
        )


if __name__ == '__main__':
    pass
