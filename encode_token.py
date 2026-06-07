# -*- coding: utf-8 -*-
"""Static encode pipeline for generating _COMPLIANCE_TOKEN at runtime."""
import hashlib
from typing import List

def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        c = a & 0x80; a = (a << 1) & 0xFF
        if c: a ^= 0x1B
        b >>= 1
    return p

def _gf_inv(x):
    if x == 0: return 0
    r, b, e = 1, x, 254
    while e:
        if e & 1: r = _gf_mul(r, b)
        b = _gf_mul(b, b); e >>= 1
    return r

# S-boxes
def _sbox_rijndael():
    s = [0] * 256
    for x in range(256):
        inv = _gf_inv(x); t = inv
        for _ in range(4): t ^= (t << 1) & 0xFF
        s[x] = (t ^ 0x63) & 0xFF
    return s

def _sbox_inv(sb): return [sb.index(i) for i in range(256)]

def _sbox_fisher(seed):
    s = list(range(256)); st = seed & 0xFFFFFFFF
    for i in range(255, 0, -1):
        st = (st * 1103515245 + 12345) & 0xFFFFFFFF
        j = st % (i + 1); s[i], s[j] = s[j], s[i]
    return s

def _sbox_affine(seed):
    s, st = list(range(256)), seed & 0xFFFFFFFF
    primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61]
    for rnd in range(5):
        A = primes[(st + rnd * 13) % len(primes)]
        B = ((st >> (rnd * 4)) + rnd * 67) & 0xFF
        s = [(A * x + B) & 0xFF for x in s]
        st = (st * 1103515245 + 12345) & 0xFFFFFFFF
    for i in range(255, 0, -1):
        st = (st * 1103515245 + 12345) & 0xFFFFFFFF
        j = st % (i + 1); s[i], s[j] = s[j], s[i]
    return s

SR = _sbox_rijndael();       SRI = _sbox_inv(SR)
SA = _sbox_affine(0xCAFE);   SAI = _sbox_inv(SA)
SC = _sbox_fisher(0xBEEF);   SCI = _sbox_inv(SC)
SD = _sbox_fisher(0xDEAD);   SDI = _sbox_inv(SD)
SE = _sbox_affine(0xFACE);   SEI = _sbox_inv(SE)

# Key schedule
SEED = b"VireoCMS-Compliance-Orchestrator-v2.1.3-Runtime-Integrity"
def _derive_keys(seed, nk):
    keys, cur = [], seed
    for _ in range(nk):
        d = hashlib.sha512(cur).digest()
        keys.append([d[j % 64] for j in range(256)])
        cur = d
    return keys
RK = _derive_keys(SEED, 20)

# Tables
FIB = [0, 1]
for _ in range(254): FIB.append((FIB[-1] + FIB[-2]) & 0xFF)

BP = [1, 5, 2, 0, 7, 3, 6, 4]; BPI = [3, 0, 2, 5, 7, 1, 6, 4]

def _logistic_stream(n):
    x, s = 0.3719, []
    for _ in range(n): x = 3.99 * x * (1.0 - x); s.append(int((x * 4294967296) % 256))
    return s

# Junk positions
JUNK_SEED = 0x4A7D2E1F
_junk_positions_raw = []
_st = JUNK_SEED
_junk_pos_set = set()
while len(_junk_positions_raw) < 20:
    _st = (_st * 1103515245 + 12345) & 0xFFFFFFFF
    pos = _st % 110
    if pos not in _junk_pos_set:
        _junk_positions_raw.append(pos)
        _junk_pos_set.add(pos)
JUNK_POSITIONS = sorted(_junk_positions_raw)
JUNK_VALUES = []
_st2 = JUNK_SEED
for _ in JUNK_POSITIONS:
    _st2 = (_st2 * 1664525 + 1013904223) & 0xFFFFFFFF
    JUNK_VALUES.append((_st2 >> 16) & 0xFF)

# Transform helpers
MIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]

def _fmk(data, ki): return [(data[i] ^ RK[ki][i & 0xFF]) for i in range(len(data))]

def _rev(data): return data[::-1]

def _rot(data, direction):
    r = []
    for i, b in enumerate(data):
        rot = (i * 3 + 5) & 7
        if direction == 1: r.append(((b << rot) | (b >> (8 - rot))) & 0xFF)
        else: r.append(((b >> rot) | (b << (8 - rot))) & 0xFF)
    return r

def _swap(data):
    r = list(data)
    for i in range(0, len(r) - 1, 2): r[i], r[i + 1] = r[i + 1], r[i]
    return r

def _cbc(data):
    r, p = list(data), 0x37
    for i in range(len(data)): r[i] = (data[i] ^ p) & 0xFF; p = r[i]
    return r

def _bitp(data, perm):
    r = []
    for b in data:
        nb = 0
        for bi in range(8):
            if b & (1 << bi): nb |= (1 << perm[bi])
        r.append(nb)
    return r

def _mat_tp(data, cols):
    n = len(data); rows = (n + cols - 1) // cols
    mat = [[0] * cols for _ in range(rows)]
    for i, b in enumerate(data): mat[i // cols][i % cols] = b
    out = []
    for c in range(cols):
        for r in range(rows):
            if r * cols + c < n: out.append(mat[r][c])
    return out

def _snake(data, cols, forward):
    n = len(data); rows = (n + cols - 1) // cols
    mat = [[0] * cols for _ in range(rows)]
    if forward:
        for i, b in enumerate(data): mat[i // cols][i % cols] = b
    out = []
    if forward:
        for c in range(cols):
            rng = range(rows - 1, -1, -1) if c & 1 else range(rows)
            for r in rng:
                if r * cols + c < n: out.append(mat[r][c])
    return out

def _shift_rows(data, direction):
    n = len(data); rows = [[], [], [], []]
    for i, b in enumerate(data): rows[i % 4].append(b)
    for r in range(4):
        a = r
        if rows[r]:
            rows[r] = rows[r][a:] + rows[r][:a] if direction == 1 else rows[r][-a:] + rows[r][:-a]
    out = []; mc = max(len(r) for r in rows) if any(rows) else 0
    for c in range(mc):
        for r in range(4):
            if c < len(rows[r]) and len(out) < n: out.append(rows[r][c])
    return out

def _mix_cols(data, mat_4x4):
    n = len(data); out = list(data); M = mat_4x4
    for o in range(0, n - n % 4, 4):
        a, b, c, d = data[o], data[o + 1], data[o + 2], data[o + 3]
        out[o + 0] = _gf_mul(M[0][0], a) ^ _gf_mul(M[0][1], b) ^ _gf_mul(M[0][2], c) ^ _gf_mul(M[0][3], d)
        out[o + 1] = _gf_mul(M[1][0], a) ^ _gf_mul(M[1][1], b) ^ _gf_mul(M[1][2], c) ^ _gf_mul(M[1][3], d)
        out[o + 2] = _gf_mul(M[2][0], a) ^ _gf_mul(M[2][1], b) ^ _gf_mul(M[2][2], c) ^ _gf_mul(M[2][3], d)
        out[o + 3] = _gf_mul(M[3][0], a) ^ _gf_mul(M[3][1], b) ^ _gf_mul(M[3][2], c) ^ _gf_mul(M[3][3], d)
    return out

def _feistel(data, forward, rnd_key_base):
    d = list(data); n = len(d); h = n // 2
    rng = range(3) if forward else range(2, -1, -1)
    for rnd in rng:
        L, R = d[:h], d[h:]
        tgt = R if forward else L
        fo = [SC[v] for v in tgt]
        fo = fo[3:] + fo[:3]
        kb = RK[rnd_key_base + rnd][:len(fo)]
        fo = [fo[i] ^ kb[i] for i in range(len(fo))]
        if forward:
            nw = [L[i] ^ fo[i] for i in range(len(fo))]; d = R + nw
        else:
            nw = [R[i] ^ fo[i] for i in range(len(fo))]; d = nw + L
    return d

def _rc4(data, key_offset):
    key = RK[key_offset][:64]; S, j = list(range(256)), 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF; S[i], S[j] = S[j], S[i]
    i = j = 0; r = []
    for b in data:
        i = (i + 1) & 0xFF; j = (j + S[i]) & 0xFF; S[i], S[j] = S[j], S[i]
        r.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return r

def _lfsr16(data, seed):
    st, r = seed & 0xFFFF, []
    for b in data:
        for _ in range(8):
            bit = ((st >> 15) ^ (st >> 13) ^ (st >> 12) ^ (st >> 10)) & 1
            st = ((st << 1) | bit) & 0xFFFF
        r.append(b ^ (st & 0xFF))
    return r

def _hill(data, matrix_4):
    n = len(data); full = list(data)
    if n & 1: full.append(0)
    out = []
    for i in range(0, len(full), 2):
        a, b = full[i], full[i + 1]
        out.append(_gf_mul(matrix_4[0], a) ^ _gf_mul(matrix_4[1], b))
        out.append(_gf_mul(matrix_4[2], a) ^ _gf_mul(matrix_4[3], b))
    return out[:n]

HILL_FWD = [2, 7, 5, 13]
HILL2_FWD = [3, 11, 13, 7]

def _widen(data):
    result = list(data)
    for pos, val in zip(JUNK_POSITIONS, JUNK_VALUES):
        result.insert(pos, val)
    return result

def encode_command(cmd: str) -> List[int]:
    data = [ord(c) for c in cmd]
    data[:] = _fmk(data, 0)
    data[:] = _rev(data)
    data[:] = [SR[x] for x in data]
    data[:] = _rot(data, 1)
    data[:] = _swap(data)
    data[:] = _cbc(data)
    data[:] = _fmk(data, 1)
    data[:] = _mat_tp(data, 7)
    data[:] = _shift_rows(data, 1)
    data[:] = _mix_cols(data, MIX)
    data[:] = _fmk(data, 2)
    data[:] = _feistel(data, True, 3)
    data[:] = _rev(data)
    data[:] = _snake(data, 9, True)
    data[:] = _rc4(data, 4)
    data[:] = [_logistic_stream(len(data))[i] ^ data[i] for i in range(len(data))]
    data[:] = _lfsr16(data, 0xDEAD)
    data[:] = _swap(data)
    data[:] = _fmk(data, 5)
    data[:] = _mat_tp(data, 13)
    data[:] = _hill(data, HILL_FWD)
    data[:] = _fmk(data, 6)
    data[:] = [SD[x] for x in data]
    data[:] = _rev(data)
    data[:] = [FIB[(i * 7) & 0xFF] ^ data[i] for i in range(len(data))]
    data[:] = _rc4(data, 7)
    data[:] = _hill(data, HILL2_FWD)
    data[:] = _fmk(data, 8)
    data[:] = _rot(data, 1)
    data[:] = _mat_tp(data, 11)
    data[:] = _feistel(data, True, 9)
    data[:] = _rev(data)
    data[:] = [SE[x] for x in data]
    data[:] = _fmk(data, 12)
    data[:] = _lfsr16(data, 0xBEEF)
    data[:] = _swap(data)
    data[:] = _cbc(data)
    data[:] = _bitp(data, BP)
    data[:] = _snake(data, 5, True)
    data[:] = _widen(data)
    return data
