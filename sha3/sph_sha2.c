#!/usr/bin/env python3
"""
sha256_32round_derive.py
========================
Derives custom 32‑round SHA‑256 constants (K32 and H32_init)
such that the 32‑round compression function is *identical*
to the standard 64‑round compression for a **specific** 64‑byte
block template (e.g., a mining header’s second chunk).

Usage:
  python3 sha256_32round_derive.py <template_hex> [--nonce-offset N]

The template is a 64‑byte hex string (128 hex digits).  The script
treats the 4 bytes at offset N (default 76, the Bitcoin nonce) as
variable and solves for K32/H32_init that work for *all* 2^32
possible values of that field.

Output:
  A C header snippet with the derived constants, ready to paste into
  sha2.c.

Requires the Z3 SMT solver (pip install z3-solver).
"""

import sys, struct
from z3 import *

if len(sys.argv) < 2:
    print("Usage: python3 sha256_32round_derive.py <template_hex> [--nonce-offset N]")
    sys.exit(1)

template_hex = sys.argv[1]
if len(template_hex) != 128:
    print("Template must be exactly 128 hex digits (64 bytes)")
    sys.exit(1)

nonce_offset = 76   # default Bitcoin nonce position inside the second block
for i, arg in enumerate(sys.argv[2:], start=2):
    if arg == '--nonce-offset' and i < len(sys.argv)-1:
        nonce_offset = int(sys.argv[i+1])
        break

template_bytes = bytes.fromhex(template_hex)
assert len(template_bytes) == 64

# ------------------------------------------------
# Standard SHA‑256 primitives in Z3
# ------------------------------------------------
def z3_rotr32(x, n):
    return RotateRight(x, n)

def z3_ch(x,y,z): return (x & y) ^ (~x & z)
def z3_maj(x,y,z): return (x & y) ^ (x & z) ^ (y & z)
def z3_sigma0(x): return z3_rotr32(x,2) ^ z3_rotr32(x,13) ^ z3_rotr32(x,22)
def z3_sigma1(x): return z3_rotr32(x,6) ^ z3_rotr32(x,11) ^ z3_rotr32(x,25)
def z3_sig0(x):   return z3_rotr32(x,7) ^ z3_rotr32(x,18) ^ LShR(x,3)
def z3_sig1(x):   return z3_rotr32(x,17) ^ z3_rotr32(x,19) ^ LShR(x,10)

def sha256_compress_64_rounds(block_bits):
    """
    Standard 64‑round compression (Z3 symbolic).
    Returns the 8 output words.
    """
    # message schedule (64 words)
    W = [BitVecVal(i, 32) for i in range(64)]   # placeholder, will set later
    # initial state (standard H0)
    state = [BitVecVal(i, 32) for i in [
        0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A,
        0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19
    ]]
    K = [BitVecVal(i, 32) for i in [
        0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,
        0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
        0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,
        0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
        0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,
        0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
        0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,
        0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
        0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,
        0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
        0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,
        0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
        0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,
        0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
        0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,
        0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2
    ]]
    # Expand message schedule
    for t in range(64):
        if t < 16:
            W[t] = block_bits[t]
        else:
            W[t] = z3_sig1(W[t-2]) + W[t-7] + z3_sig0(W[t-15]) + W[t-16]
    a,b,c,d,e,f,g,h = state
    for t in range(64):
        T1 = h + z3_sigma1(e) + z3_ch(e,f,g) + K[t] + W[t]
        T2 = z3_sigma0(a) + z3_maj(a,b,c)
        h = g; g = f; f = e; e = d + T1
        d = c; c = b; b = a; a = T1 + T2
    return [a + state[0], b + state[1], c + state[2], d + state[3],
            e + state[4], f + state[5], g + state[6], h + state[7]]

def sha256_compress_32_rounds(block_bits, K32, Hinit):
    """
    32‑round compression with custom constants and initial state.
    Both K32 and Hinit are Z3 bitvector arrays of length 32 and 8.
    """
    W = [BitVecVal(0,32) for _ in range(32)]
    for t in range(16):
        W[t] = block_bits[t]
    for t in range(16,32):
        W[t] = z3_sig1(W[t-2]) + W[t-7] + z3_sig0(W[t-15]) + W[t-16]
    a,b,c,d,e,f,g,h = Hinit
    for t in range(32):
        T1 = h + z3_sigma1(e) + z3_ch(e,f,g) + K32[t] + W[t]
        T2 = z3_sigma0(a) + z3_maj(a,b,c)
        h = g; g = f; f = e; e = d + T1
        d = c; c = b; b = a; a = T1 + T2
    # No feed‑forward in our custom design – the Hinit already encodes it.
    return [a, b, c, d, e, f, g, h]

# ------------------------------------------------
# Build symbolic block incorporating the nonce
# ------------------------------------------------
block_bits = []
for i in range(64):
    if i == nonce_offset:
        nonce_var = BitVec('nonce', 32)
        block_bits.append(nonce_var)
    else:
        byte_val = template_bytes[i]
        # Convert 4 bytes to 32‑bit big‑endian integer (we store the actual word)
        if i % 4 == 0:
            word = struct.unpack(">I", template_bytes[i:i+4])[0]
            block_bits.append(BitVecVal(word, 32))
        # We already added the whole word when i is 0,4,8,... so skip the next three bytes
        if i % 4 == 0:
            i += 3  # move to next word
    # The loop increments normally; careful with indexing
    # This is tricky; instead, pre‑compute 16 words.
words = []
for j in range(16):
    offset = j*4
    if offset == nonce_offset:
        words.append(BitVec('nonce', 32))
    else:
        words.append(BitVecVal(struct.unpack(">I", template_bytes[offset:offset+4])[0], 32))
block_bits = words   # now 16 symbolic words

# Standard 64‑round output (symbolic, depends on nonce)
out64 = sha256_compress_64_rounds(block_bits)

# Create unknown constants for 32‑round variant
K32 = [BitVec(f"K32_{t}", 32) for t in range(32)]
Hinit = [BitVec(f"Hinit_{j}", 32) for j in range(8)]

out32 = sha256_compress_32_rounds(block_bits, K32, Hinit)

# Equality constraint for all possible nonce values
s = Solver()
s.add(ForAll([nonce_var], And([out64[i] == out32[i] for i in range(8)])))

print("[*] Solving for K32 and Hinit... (this may take a few minutes)")
if s.check() == sat:
    m = s.model()
    print("[+] Solution found!")
    # Extract constants
    K32_vals = [m.evaluate(K32[t]).as_long() for t in range(32)]
    Hinit_vals = [m.evaluate(Hinit[j]).as_long() for j in range(8)]
    # Print as C snippet
    print("\n/* Paste this into sha2.c */")
    print("static const sph_u32 H32_init[8] = {")
    for j in range(0,8,4):
        print("    ", end="")
        for k in range(j, min(j+4,8)):
            print(f"SPH_C32(0x{Hinit_vals[k]:08X}), ", end="")
        print()
    print("};")
    print("static const sph_u32 K32[32] = {")
    for t in range(0,32,4):
        print("    ", end="")
        for k in range(t, min(t+4,32)):
            print(f"SPH_C32(0x{K32_vals[k]:08X}), ", end="")
        print()
    print("};")
else:
    print("[-] No solution found.  Try a different block template or nonce offset.")
