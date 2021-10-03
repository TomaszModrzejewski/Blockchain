# Blockchain version
VERSION = 1

# Reward of coinbase transactions
REWARD = 3000000000

# Seconds in ten minutes
TEN_MINUTES = 60 * 10

# Maximum target
MAX_TARGET = 0xffffff * 256 ** (0x1d - 3)

# Sighash type
SIGHASH_ALL = 1

# Bits for maximum target
BITS = bytes.fromhex('ffffff1d')


if __name__ == '__main__':
    pass
