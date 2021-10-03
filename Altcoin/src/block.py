from dataclasses import dataclass

from hash import sha256
from tx import Transaction
from utils import (
    bits_to_target,
    int_to_little_endian,
    int_to_varint,
    little_endian_to_int,
    varint_to_int,
)


@dataclass
class BlockHeader:

    """
    Python class for block headers
    """

    version: int
    parent_hash: bytes
    merkle_root: bytes
    bits: int
    timestamp: int
    nonce: int

    def encode(self):

        """
        Encoding block header to bytes
        """

        return bytes(
            int_to_little_endian(self.version, 4) +
            self.parent_hash[::-1] +
            self.merkle_root[::-1] +
            self.bits +
            int_to_little_endian(self.timestamp, 4) +
            int_to_little_endian(self.nonce, 4)
        )

    @classmethod
    def decode(cls, s):

        """
        Decoding bytes encoded block header
        """

        return cls(
            little_endian_to_int(s.read(4)),
            s.read(32)[::-1],
            s.read(32)[::-1],
            s.read(4),
            little_endian_to_int(s.read(4)),
            little_endian_to_int(s.read(4)),
        )


@dataclass
class Block:

    """
    Python class for blocks
    """

    header: BlockHeader
    transactions: [Transaction]

    def id(self):

        """
        Hash in hexadecimals
        """

        return self.to_hash().hex()

    def to_hash(self):

        """
        Block header hash reversed
        """

        return sha256(self.header.encode())[::-1]

    def target(self):

        """
        Compute block's mining target
        """

        return bits_to_target(self.header.bits)

    def difficulty(self):

        """
        Compute mining difficulty
        """

        min_diff = 0xffffff * 256 ** (0x1d - 3)
        return min_diff / self.target()

    def validate(self):

        """
        Verify block's proof of work
        """

        if int(self.id(), 16) >= self.target():
            return False

        return True

    def encode(self):

        """
        Encoding block to bytes
        """

        # Number of transactions
        serialized = bytes()
        txs = len(self.transactions)

        # Block header
        serialized += self.header.encode()
        serialized += int_to_varint(txs)

        # Transactions
        for tx in self.transactions:
            serialized += tx.encode()

        return serialized

    @classmethod
    def decode(cls, s):

        """
        Decoding bytes encoded block
        """

        # Number of transactions
        header = BlockHeader.decode(s)
        tx_count = varint_to_int(s)

        transactions = []

        # Transactions
        for i in range(tx_count):

            tx = Transaction.decode(s)
            transactions.append(tx)

        return cls(header, transactions)


if __name__ == '__main__':
    pass
