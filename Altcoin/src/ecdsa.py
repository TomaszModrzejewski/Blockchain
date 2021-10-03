"""

ABOUT:

 This is a pure python implementation of ECC made to be
 fast and secured, using elegant maths such as Jacobian
 coordinates to speed up ECDSA, and using secured point
 multiplication method such as the Montgomery Ladder to
 protect against side-channel attacks.

 There is no nonce reuse. Nonces are generated as described
 per RFC6979. The default curve used throughout the package
 is secp256k1, which provides 256 bits of security. All the
 points are validated before any operation.

DISCLAIMER:

 All that being said, crypto is tricky, and i'm not beyond
 making mistakes. It may contain some miss-implementations
 leading to security issues.

"""

from dataclasses import dataclass

import hashlib
import hmac
import io
import os

import base58


@dataclass
class Point:

    """
    Point in jacobian coordinates
    """

    x: int = 0
    y: int = 0
    z: int = 0

    def is_on_curve(self):

        """
        Is point included in curve ?
        """

        x, y = self.x, self.y

        y2 = (y ** 2) % P
        x2 = (x ** 3 + A * x + B) % P

        return y2 == x2


# See http://www.secg.org/sec2-v2.pdf for curve params
# Params based on bitcoin's curve : secp256k1

A = 0
B = 7

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

G = Point(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def gen_key_pair():

    """
    Generate key pair
    """

    sk = gen_secret_key()
    vk = point_mul(G, sk)

    return sk, pubkey_to_sec(vk)


def sign(msg, secret, is_safe=False):

    """
    Sign message using secret key
    """

    z = bytes_to_int(msg)  # Msg to integer
    k = deterministic_k(z, secret)  # Generate nonce

    k_inv = mod_inv(k, N)  # Inverse of k % N
    r = point_mul(G, k, is_safe)  # k * G

    s = (z + r.x * secret) * k_inv
    s = s if s * 2 < N else N - s

    return sig_to_der(r.x % N, s % N)


def verify(msg, sig, key, is_safe=False):

    """
    Verify signature using public key
    """

    r, s = der_to_sig(sig)  # Signature
    K = sec_to_pubkey(key)  # Public key

    # Check public key point
    if not K.is_on_curve():
        return False

    # Check that r is valid
    if not 1 <= r <= N:
        return False

    # Check that s is valid
    if not 1 <= s <= N:
        return False

    z = bytes_to_int(msg)  # Msg to integer
    s_inv = mod_inv(s, N)  # Inverse of s % N

    u = (z * s_inv) % N
    v = (r * s_inv) % N

    u = point_mul(G, u, is_safe)  # u = G * u
    v = point_mul(K, v, is_safe)  # v = K * v

    return point_add(u, v).x == r


def secret_to_wif(s):

    """
    Encoding secret key ot WIF
    """

    s_bytes = s.to_bytes(32, 'big')
    return base58.b58encode_check(b'\x80' + s_bytes)


def wif_to_secret(wif):

    """
    Decoding WIF encoded secret key
    """

    return base58.b58decode(wif)[:-4]


def sig_to_pubkey(msg, sig, is_safe=False):

    """
    Recover public key from signature
    """

    r, s = der_to_sig(sig)

    y = (pow(r, 3, P) + 7) % P
    y = pow(y, (P + 1) // 4, P)

    z = bytes_to_int(msg)

    Gz = point_mul(Point(G.x, G.y, 1), (N - z) % N, is_safe)
    XY = point_mul(Point(r, y, 1), s, is_safe)

    Qr = point_add(Gz, XY)

    return point_mul(Qr, mod_inv(r, N), is_safe)


def sec_to_pubkey(sec):

    """
    Decoding SEC encoded public key
    """

    s = io.BytesIO(sec)
    prefix = s.read(1)[0]

    # If key not compressed
    if prefix == 4:

        x = int.from_bytes(s.read(32), 'big')
        y = int.from_bytes(s.read(32), 'big')

        return Point(x, y)

    else:

        # First recover full 'x' coordinate
        x = int.from_bytes(s.read(32), 'big')

        # Solve y^2 = x^3 + 7 for y, but mod p
        y = (pow(x, 3, P) + 7) % P
        y = pow(y, (P + 1) // 4, P)

        # Extract the y-evenness
        if (y % 2 == 0) != (prefix == 2):
            return Point(x, P - y)
        else:
            return Point(x, y)


def pubkey_to_sec(p, compressed=True):

    """
    Encoding public key to SEC
    """

    # Coordinates to bytes
    x_bytes = p.x.to_bytes(32, 'big')
    y_bytes = p.y.to_bytes(32, 'big')

    # if compressed format required
    if not compressed:
        return b'\x04' + x_bytes + y_bytes

    # Check y-evenness
    if p.y % 2 == 0:
        return b'\x02' + x_bytes
    else:
        return b'\x03' + x_bytes


def sig_to_der(r, s):

    """
    Encoding signature to DER
    """

    result = bytes()

    # Integers to big endian
    rbin = r.to_bytes(32, 'big')
    sbin = s.to_bytes(32, 'big')

    # Remove all null bytes at the beginning
    rbin = rbin.lstrip(b'\x00')
    sbin = sbin.lstrip(b'\x00')

    # if bin has a high bit, add a \x00
    if rbin[0] & 0x80:
        rbin = b'\x00' + rbin

    if sbin[0] & 0x80:
        sbin = b'\x00' + sbin

    # Add bytes of r and s
    result += bytes([2, len(rbin)]) + rbin
    result += bytes([2, len(sbin)]) + sbin

    # Prepend prefix of DER format
    prefix = bytes([0x30, len(result)])

    return prefix + result


def der_to_sig(sig):

    """
    Decoding DER encoded signature
    """

    s = io.BytesIO(sig)

    # Check first byte
    if s.read(1)[0] != 0x30:
        raise SyntaxError("Bad Signature")

    # Check sig length
    if s.read(1)[0] + 2 != len(sig):
        raise SyntaxError("Bad Signature")

    # Check sig.r prefix
    if s.read(1)[0] != 0x02:
        raise SyntaxError("Bad Signature")

    # Read r integer
    rl = s.read(1)[0]
    r = int.from_bytes(s.read(rl), 'big')

    # Check sig.s prefix
    if s.read(1)[0] != 0x02:
        raise SyntaxError("Bad Signature")

    # Read s integer
    sl = s.read(1)[0]
    s = int.from_bytes(s.read(sl), 'big')

    # Check bytes length
    if len(sig) != 6 + rl + sl:
        raise SyntaxError("Bad Signature")

    return r, s


def bytes_to_int(msg):

    """
    Convert bytes string to integer
    """

    msg_hash = hashlib.sha512(msg).digest()
    e = int.from_bytes(msg_hash, 'big')

    # FIPS 180 says that when a hash needs to be truncated,
    # the rightmost bits should be discarded.

    return e >> (e.bit_length() - N.bit_length())


def to_hmac(k, v):

    """
    Compute sha256 hmac digest
    """

    return hmac.new(k, v, hashlib.sha256).digest()


def deterministic_k(z, s):

    """
    Generates deterministic nonce 'k'
    as described per RFC6979
    """

    k = b'\x00' * 32
    v = b'\x01' * 32

    z = z - N if z > N else z

    z_bytes = z.to_bytes(32, 'big')
    s_bytes = s.to_bytes(32, 'big')

    k = to_hmac(k, v + b'\x00' + s_bytes + z_bytes)
    v = to_hmac(k, v)
    k = to_hmac(k, v + b'\x01' + s_bytes + z_bytes)
    v = to_hmac(k, v)

    while True:

        t = b''

        while len(t) * 8 < 256:

            v = to_hmac(k, v)
            t += v

        k_choice = int.from_bytes(v, 'big')

        if 1 <= k_choice < N:
            break

        k = to_hmac(k, v + b'\x00')
        v = to_hmac(k, v)

    return k_choice


def gen_secret_key():

    """
    Secret key pseudo-random generator
    """

    while True:

        key = int.from_bytes(os.urandom(32), 'big')

        if 1 <= key < N:  # The key is valid
            break  # Break out

    return key


def point_add(p, q):

    """
    Elliptic curves point addition
    """

    return _from_jacobian(
        _jacobian_add(
            _to_jacobian(p),
            _to_jacobian(q),
        )
    )


def point_mul(p, n, is_safe=False):

    """
    Elliptic curves point multiplication
    """

    if is_safe:

        return _from_jacobian(
            _safe_mul(
                _to_jacobian(p),
                n,
            )
        )

    else:

        return _from_jacobian(
            _fast_mul(
                _to_jacobian(p),
                n,
            ),
        )


def mod_inv(k, p):

    """
    Find integer x such that:
    (x * k) % p == 1
    """

    if k == 0:
        return 0

    if k < 0:
        return p - mod_inv(-k, p)

    # Extended Euclidean algorithm

    s, s1 = 0, 1
    t, t1 = 1, 0
    r, r1 = p, k

    while r != 0:
        q = r1 // r
        r1, r = r, r1 - q * r
        s1, s = s, s1 - q * s
        t1, t = t, t1 - q * t

    return s1 % p


def _jacobian_add(p, q):

    """
    Jacobian point addition
    """

    if not p.y:
        return q

    if not q.y:
        return p

    U1 = (p.x * q.z ** 2) % P
    U2 = (q.x * p.z ** 2) % P
    S1 = (p.y * q.z ** 3) % P
    S2 = (q.y * p.z ** 3) % P

    if U1 == U2:
        if S1 == S2:
            return _jacobian_double(p)
        return Point(0, 0, 1)

    H1 = U2 - U1
    R1 = S2 - S1

    H2 = (H1 * H1) % P
    H3 = (H1 * H2) % P

    U1H2 = (U1 * H2) % P

    nx = (R1 ** 2 - H3 - 2 * U1H2) % P
    ny = (R1 * (U1H2 - nx) - S1 * H3) % P
    nz = (H1 * p.z * q.z) % P

    return Point(nx, ny, nz)


def _jacobian_double(p):

    """
    Jacobian point doubling
    """

    if not p.y:
        return Point(0, 0, 0)

    ysq = (p.y ** 2) % P

    S = (4 * p.x * ysq) % P
    M = (3 * p.x ** 2 + A * p.z ** 4) % P

    nx = (M ** 2 - 2 * S) % P
    ny = (M * (S - nx) - 8 * ysq ** 2) % P
    nz = (2 * p.y * p.z) % P

    return Point(nx, ny, nz)


def _safe_mul(p, n):

    """
    Point multiplication by scalar using
    montgomery-ladder algorithm

    Safest way to multiply in elliptic curves
    """

    R0 = Point(0, 0, 1)
    R1 = p

    for i in range(N.bit_length(), -1, -1):

        if (n >> i & 1) == 0:

            R1 = _jacobian_add(R0, R1)
            R0 = _jacobian_double(R0)

        else:

            R0 = _jacobian_add(R0, R1)
            R1 = _jacobian_double(R1)

    return R0


def _fast_mul(p, n):

    """
    Point multiplication by scalar using
    double-and-add algorithm

    Fastest way to multiply in elliptic curves
    """

    if p.y == 0 or n == 0:
        return Point(0, 0, 1)

    if n == 1:
        return p

    if n < 0 or n >= N:
        return _fast_mul(p, n % N)

    if (n % 2) == 0:

        return _jacobian_double(
            _fast_mul(
                p,
                n // 2,
            )
        )

    # (n % 2) == 1:
    return _jacobian_add(
        _jacobian_double(
            _fast_mul(
                p,
                n // 2,
            )
        ),
        p,
    )


def _from_jacobian(p):

    """
    Point from jacobian coordinates
    """

    z = mod_inv(p.z, P)

    return Point(
        (p.x * z ** 2) % P,
        (p.y * z ** 3) % P,
    )


def _to_jacobian(p):

    """
    Point in jacobian coordinates
    """

    return Point(p.x, p.y, 1)


if __name__ == '__main__':
    pass
