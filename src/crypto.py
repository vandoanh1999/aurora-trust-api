"""
Aurora Trust Compliance API — Cryptographic Core
Pure Python 3 implementation (no `six` dependency).
Shamir's Secret Sharing over GF(p) + ECC P-256 signing.
"""
import os
import uuid
import hmac
import string
import hashlib
import secrets
from typing import List, Tuple

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# ── Shamir's Secret Sharing ──────────────────────────────────────────────────
_PRIME = 115792089237316195423570985008687907853269984665640564039457584007913129639747
_CHARSET = string.hexdigits[:16]


def _int_to_hex(n: int, pad: int = 0) -> str:
    if n == 0:
        return _CHARSET[0].zfill(max(pad, 1))
    out = ""
    while n > 0:
        n, d = divmod(n, 16)
        out += _CHARSET[d]
    return out[::-1].zfill(pad)


def _hex_to_int(s: str) -> int:
    out = 0
    for c in s:
        out = out * 16 + _CHARSET.index(c)
    return out


def _mod_inv(a: int, m: int) -> int:
    return pow(a, -1, m)


def _lagrange(x: int, xs: List[int], ys: List[int]) -> int:
    y = 0
    for i in range(len(xs)):
        li = 1
        for j in range(len(xs)):
            if i != j:
                li = li * (x - xs[j]) * _mod_inv(xs[i] - xs[j], _PRIME) % _PRIME
        y = (_PRIME + y + ys[i] * li) % _PRIME
    return y


def split_secret(secret_hex: str, k: int, n: int) -> List[str]:
    """Split a hex-encoded secret into n shares requiring k to reconstruct."""
    secret_int = _hex_to_int(secret_hex)
    if secret_int >= _PRIME:
        raise ValueError("Secret too large for prime field.")
    coeffs = [secret_int] + [secrets.randbelow(_PRIME) for _ in range(k - 1)]
    shares = []
    for x in range(1, n + 1):
        y = sum(coeffs[i] * pow(x, i, _PRIME) for i in range(len(coeffs))) % _PRIME
        shares.append(f"{_int_to_hex(x, 1)}-{_int_to_hex(y, len(secret_hex))}")
    return shares


def recover_secret(shares: List[str]) -> str:
    """Recover a hex-encoded secret from k shares."""
    xs, ys = [], []
    for s in shares:
        parts = s.split("-")
        xs.append(_hex_to_int(parts[0]))
        ys.append(_hex_to_int(parts[1]))
    result = _lagrange(0, xs, ys)
    # Determine pad length from first share
    pad = len(shares[0].split("-")[1])
    return _int_to_hex(result, pad)


# ── ECC P-256 Key Management ─────────────────────────────────────────────────

def generate_node_keypair(seed: bytes = None) -> Tuple[ECC.EccKey, ECC.EccKey]:
    """Generate an ECC P-256 keypair. Optionally seeded (deterministic)."""
    if seed:
        priv = ECC.generate(curve="P-256", randfunc=lambda n: seed[:n])
    else:
        priv = ECC.generate(curve="P-256")
    return priv, priv.public_key()


def ecc_sign(private_key: ECC.EccKey, message: bytes) -> str:
    """Sign a message and return hex-encoded DER signature."""
    h = SHA256.new(message)
    sig = DSS.new(private_key, "fips-186-3").sign(h)
    return sig.hex()


def ecc_verify(public_key: ECC.EccKey, message: bytes, sig_hex: str) -> bool:
    """Verify an ECC P-256 signature."""
    try:
        h = SHA256.new(message)
        DSS.new(public_key, "fips-186-3").verify(h, bytes.fromhex(sig_hex))
        return True
    except (ValueError, TypeError):
        return False


# ── HMAC-based VC Signing ────────────────────────────────────────────────────

def hmac_sign(payload: bytes, key: bytes) -> str:
    return hmac.new(key, payload, digestmod=hashlib.sha256).hexdigest()


def hmac_verify(payload: bytes, key: bytes, signature: str) -> bool:
    expected = hmac_sign(payload, key)
    return hmac.compare_digest(expected, signature)


# ── Threshold Signature Scheme ───────────────────────────────────────────────

class ThresholdScheme:
    """
    (k, n) threshold scheme:
      - Generate a master P-256 key
      - Split private key into n shares
      - Any k shares can reconstruct and sign
    """

    def __init__(self, k: int, n: int):
        self.k = k
        self.n = n
        priv, pub = generate_node_keypair()
        self.public_key = pub
        priv_hex = priv.d.to_bytes(32, "big").hex()
        self.shares = split_secret(priv_hex, k, n)

    def sign_with_quorum(self, shares: List[str], message: bytes) -> str:
        if len(shares) < self.k:
            raise ValueError(f"Need at least {self.k} shares, got {len(shares)}.")
        priv_hex = recover_secret(shares[:self.k])
        priv_bytes = bytes.fromhex(priv_hex)
        key = ECC.construct(curve="P-256", d=int.from_bytes(priv_bytes, "big"))
        return ecc_sign(key, message)

    def verify(self, message: bytes, sig_hex: str) -> bool:
        return ecc_verify(self.public_key, message, sig_hex)

    @property
    def public_key_pem(self) -> str:
        return self.public_key.export_key(format="PEM")
