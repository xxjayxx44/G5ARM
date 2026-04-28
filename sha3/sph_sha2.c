#!/usr/bin/env python3
"""
Derive custom 32‑round SHA‑256 constants for a specific block template.
Usage: python3 sha256_32round_derive.py <template_hex> [--nonce-offset N]
template_hex : 128 hex digits (64 bytes) of the second block.
"""
import sys, struct
from z3 import *

if len(sys.argv) < 2 or len(sys.argv[1]) != 128:
    print("Usage: python3 sha256_32round_derive.py <128‑hex‑digit template>")
    sys.exit(1)

template_hex = sys.argv[1]
nonce_offset = 76
for i in range(2, len(sys.argv)):
    if sys.argv[i] == "--nonce-offset":
        nonce_offset = int(sys.argv[i+1])

template_bytes = bytes.fromhex(template_hex)

# Z3 symbolic SHA‑256 components
def z3_rotr32(x, n): return RotateRight(x, n)
def z3_sigma0(x): return z3_rotr32(x,2) ^ z3_rotr32(x,13) ^ z3_rotr32(x,22)
def z3_sigma1(x): return z3_rotr32(x,6) ^ z3_rotr32(x,11) ^ z3_rotr32(x,25)
def z3_ch(x,y,z): return (x & y) ^ (~x & z)
def z3_maj(x,y,z): return (x & y) ^ (x & z) ^ (y & z)
def z3_sig0(x):   return z3_rotr32(x,7) ^ z3_rotr32(x,18) ^ LShR(x,3)
def z3_sig1(x):   return z3_rotr32(x,17) ^ z3_rotr32(x,19) ^ LShR(x,10)

def sha256_64(block):
    # block is list of 16 symbolic 32‑bit words
    W = [None]*64
    K = [BitVecVal(k,32) for k in [
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
    state = [BitVecVal(v,32) for v in [0x6A09E667,0xBB67AE85,0x3C6EF372,
                0xA54FF53A,0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19]]
    for t in range(64):
        W[t] = block[t] if t<16 else z3_sig1(W[t-2]) + W[t-7] + z3_sig0(W[t-15]) + W[t-16]
    a,b,c,d,e,f,g,h = state
    for t in range(64):
        T1 = h + z3_sigma1(e) + z3_ch(e,f,g) + K[t] + W[t]
        T2 = z3_sigma0(a) + z3_maj(a,b,c)
        h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2
    return [a+state[0], b+state[1], c+state[2], d+state[3],
            e+state[4], f+state[5], g+state[6], h+state[7]]

def sha256_32(block, Hinit, K32):
    W = [None]*32
    for t in range(16):
        W[t] = block[t]
    for t in range(16,32):
        W[t] = z3_sig1(W[t-2]) + W[t-7] + z3_sig0(W[t-15]) + W[t-16]
    a,b,c,d,e,f,g,h = Hinit
    for t in range(32):
        T1 = h + z3_sigma1(e) + z3_ch(e,f,g) + K32[t] + W[t]
        T2 = z3_sigma0(a) + z3_maj(a,b,c)
        h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2
    return [a, b, c, d, e, f, g, h]

# Build symbolic block with variable nonce
words = []
for j in range(16):
    off = j*4
    if off == nonce_offset:
        words.append(BitVec('nonce', 32))
    else:
        val = struct.unpack(">I", template_bytes[off:off+4])[0]
        words.append(BitVecVal(val, 32))

out64 = sha256_64(words)

H_sym = [BitVec(f"Hinit_{j}",32) for j in range(8)]
K_sym = [BitVec(f"K32_{t}",32) for t in range(32)]
out32 = sha256_32(words, H_sym, K_sym)

s = Solver()
s.add(ForAll([words[nonce_offset//4]], And([out64[i]==out32[i] for i in range(8)])))

print("[*] Solving for constants...")
if s.check() == sat:
    m = s.model()
    H_vals = [m.evaluate(H_sym[j]).as_long() for j in range(8)]
    K_vals = [m.evaluate(K_sym[t]).as_long() for t in range(32)]
    print("\n/* Paste into sha2.c */")
    print("static const sph_u32 H32_init[8] = {")
    print("    ", ", ".join(f"SPH_C32(0x{v:08X})" for v in H_vals), "};")
    print("static const sph_u32 K32[32] = {")
    for i in range(0,32,4):
        print("    ", ", ".join(f"SPH_C32(0x{K_vals[j]:08X})" for j in range(i,min(i+4,32))), end="")
        if i+4 < 32: print(",")
        else: print("\n};")
else:
    print("Failed. Ensure z3 is installed and template is correct.")
