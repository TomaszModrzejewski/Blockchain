from dataclasses import dataclass

from ecdsa import sign
from hash import sha256
from script import Script
from utils import (
    int_to_little_endian,
    int_to_varint,
    little_endian_to_int,
    varint_to_int,
)


REWARD = 3000000000
SIGHASH_ALL = 1


@dataclass
class TxIn:

    """
    Python class for transaction inputs
    """

    prev_tx: bytes
    prev_index: int
    script_sig: Script

    def copy(self):

        """
        Copy of this transaction input
        """

        return TxIn(
            self.prev_tx,
            self.prev_index,
            Script()
        )

    def encode(self):

        """
        Encoding transaction input to bytes
        """

        return bytes(
            self.prev_tx[::-1] +
            int_to_little_endian(self.prev_index, 4) +
            self.script_sig.encode()
        )

    @classmethod
    def decode(cls, s):

        """
        Decoding bytes encoded transaction input
        """

        return cls(
            s.read(32)[::-1],
            little_endian_to_int(s.read(4)),
            Script.decode(s)
        )


@dataclass
class TxOut:

    """
    Python class for transaction outputs
    """

    amount: int
    script_pubkey: Script

    def copy(self):

        """
        Copy of this transaction output
        """

        return TxOut(
            self.amount,
            self.script_pubkey
        )

    def encode(self):

        """
        Encoding transaction output to bytes
        """

        return bytes(
            int_to_little_endian(self.amount, 8) +
            self.script_pubkey.encode()
        )

    @classmethod
    def decode(cls, s):

        """
        Decoding bytes encoded transaction output
        """

        return cls(
            little_endian_to_int(s.read(8)),
            Script.decode(s)
        )


@dataclass
class Transaction:

    """
    Python class for transactions
    """

    version: int
    inputs: [TxIn]
    outputs: [TxOut]

    def to_hash(self):

        """
        Transaction hash
        """

        return sha256(self.encode())[::-1]

    def is_coinbase(self):

        """
        Is it a coinbase transaction
        """

        if len(self.inputs) != 1:
            return False

        if self.inputs[0].prev_tx != b'\x00' * 32:
            return False

        if sum([e.amount for e in self.outputs]) != REWARD:
            return False

        if self.inputs[0].prev_index != 0xffffffff:
            return False

        return True

    def coinbase_height(self):

        """
        Block number of the transaction
        """

        if not self.is_coinbase():
            return None

        first_cmd = self.inputs[0].script_sig.cmds[0]
        return little_endian_to_int(first_cmd)

    def sign(self, sk, vk):

        """
        Sign transaction inputs
        """

        self.copy()

        for i in range(len(self.inputs)):
            self.sign_input(i, sk, vk)

    def verify(self, scripts):

        """
        Verify transaction inputs
        """

        sigs = []

        # Get script sigs
        for tx_in in self.inputs:
            sigs.append(tx_in.script_sig)

        # Copy transaction
        self.copy()

        # Verify input scripts
        for i in range(len(self.inputs)):
            if not self.verify_input(sigs[i], scripts[i]):
                return False

        return True

    def sign_input(self, index, sk, vk):

        """
        Sign transaction input
        """

        # Transaction hash
        sig_hash = self.to_hash()

        # Compute DER signature
        der = sign(sig_hash, sk).encode()
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')

        # Set transaction input script sig
        self.inputs[index].script_sig = Script([sig, vk.encode()])

    def verify_input(self, script_sig, script_pubkey):

        """ Verify transaction input """

        # Hash to sign
        sig_hash = self.to_hash()

        # Combine transaction scripts
        combined = script_sig + script_pubkey

        # Evaluate combined
        return combined.evaluate(sig_hash)

    def copy(self):

        """
        Create a copy of this transaction
        """

        self.version = self.version

        inputs = []

        # Copy inputs
        for tx_in in self.inputs:
            inputs.append(tx_in.copy())

        self.inputs = inputs

        outputs = []

        # Copy outputs
        for tx_out in self.outputs:
            outputs.append(tx_out.copy())

        self.outputs = outputs

    def encode(self):

        """
        Transaction header to bytes
        """

        serialized = bytes()

        v = self.version
        serialized += int_to_little_endian(v, 4)

        # Number of inputs
        b = len(self.inputs)
        serialized += int_to_varint(b)

        # Serialize inputs
        for tx_in in self.inputs:
            serialized += tx_in.encode()

        # Number of outputs
        b = len(self.outputs)
        serialized += int_to_varint(b)

        # Serialize outputs
        for tx_out in self.outputs:
            serialized += tx_out.encode()

        return serialized

    @classmethod
    def decode(cls, s):

        """
        Bytes to transaction header
        """

        inputs = []

        v = little_endian_to_int(s.read(4))

        # Number of inputs
        n_ins = varint_to_int(s)

        # Parse input
        for i in range(n_ins):
            inputs.append(TxIn.decode(s))

        outputs = []

        # Number of outputs
        n_outs = varint_to_int(s)

        # Parse output
        for i in range(n_outs):
            outputs.append(TxOut.decode(s))

        return cls(v, inputs, outputs)


if __name__ == '__main__':
    pass
