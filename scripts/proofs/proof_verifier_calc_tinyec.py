#!/usr/bin/env python

"""
Zero Knowledge Verifier Proof Tool (P-256)
Supports both:
  1) Command-line mode (all parameters passed as flags)
  2) Interactive mode (-i / --interactive), where you are prompted for each value
"""

import argparse
from tinyec import registry, ec
from hashlib import sha256

# Utility function to parse decimal or hex input
def parse_input(s):
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16 )
    else:
        return int(s, 10 )

# Set up argument parser
parser = argparse.ArgumentParser(
    description="Zero Knowledge Verifier Proof Tool (P-256)"
)
parser.add_argument(
    '-i', '--interactive',
    action='store_true',
    help='Run in interactive mode (will prompt for each parameter).'
)
parser.add_argument('-gx',   type=parse_input, help='g_x coordinate (decimal or hex)')
parser.add_argument('-gy',   type=parse_input, help='g_y coordinate (decimal or hex)')
parser.add_argument('-hx',   type=parse_input, help='h_x coordinate (decimal or hex)')
parser.add_argument('-hy',   type=parse_input, help='h_y coordinate (decimal or hex)')
parser.add_argument('-COMx', type=parse_input, help='COM_x coordinate (decimal or hex)')
parser.add_argument('-COMy', type=parse_input, help='COM_y coordinate (decimal or hex)')
parser.add_argument('-Px',   type=parse_input, help='P_x coordinate (decimal or hex)')
parser.add_argument('-Py',   type=parse_input, help='P_y coordinate (decimal or hex)')
parser.add_argument('-n',    type=parse_input, help='nonce scalar (decimal or hex)')
parser.add_argument('-v',    type=parse_input, help='scalar v (decimal or hex)')
parser.add_argument('-w',    type=parse_input, help='scalar w (decimal or hex)')

args = parser.parse_args()

# Load curve
curve = registry.get_curve('secp256r1')

def point_from_coords(x, y):
    return ec.Point(curve, x, y)

# If interactive flag is set, ignore other flags and prompt
if args.interactive:
    print("=== Zero Knowledge Verifier Proof Tool (Interactive Mode) ===\n")

    # 2) Input base points
    print("Step 2: Input coordinates for g and h (decimal or hex with 0x prefix)")
    g_x = parse_input(input("Enter g_x: "))
    g_y = parse_input(input("Enter g_y: "))
    g = point_from_coords(g_x, g_y)
    print(f"g = E(({hex(g_x)}, {hex(g_y)})) -> {g}")

    h_x = parse_input(input("Enter h_x: "))
    h_y = parse_input(input("Enter h_y: "))
    h = point_from_coords(h_x, h_y)
    print(f"h = E(({hex(h_x)}, {hex(h_y)})) -> {h}\n")

    # 3) Input COM commitment
    print("Step 3: Input coordinates for COM (decimal or hex with 0x prefix)")
    com_x = parse_input(input("Enter COM_x: "))
    com_y = parse_input(input("Enter COM_y: "))
    COM = point_from_coords(com_x, com_y)
    print(f"COM = E(({hex(com_x)}, {hex(com_y)})) -> {COM}\n")

    # 4) Nonce
    print("Step 4: Enter scalar nonce (decimal or hex with 0x prefix)")
    nonce = parse_input(input("Enter nonce: "))
    print(f"nonce = {hex(nonce)}\n")

    # 5) Input P commitment
    print("Step 5: Input coordinates for P (decimal or hex with 0x prefix)")
    P_x = parse_input(input("Enter P_x: "))
    P_y = parse_input(input("Enter P_y: "))
    P = point_from_coords(P_x, P_y)
    print(f"P = E(({hex(P_x)}, {hex(P_y)})) -> {P}\n")

    # 6) Scalars v and w
    print("Step 6: Enter scalars v and w (decimal or hex with 0x prefix)")
    v = parse_input(input("Enter v: "))
    w = parse_input(input("Enter w: "))
    print(f"v = {hex(v)}, w = {hex(w)}\n")

else:
    # Non-interactive: ensure all parameters are provided
    required_fields = ['gx','gy','hx','hy','COMx','COMy','Px','Py','n','v','w']
    missing = [f for f in required_fields if getattr(args, f) is None]
    if missing:
        parser.error(f"In non-interactive mode, the following arguments are required: {', '.join('-' + m for m in missing)}")

    print("=== Zero Knowledge Verifier Proof Tool (CLI Mode) ===\n")

    # 2) Assign base points from args
    g_x, g_y = args.gx, args.gy
    g = point_from_coords(g_x, g_y)
    print(f"Step 2: g = E(({hex(g_x)}, {hex(g_y)})) -> {g}")

    h_x, h_y = args.hx, args.hy
    h = point_from_coords(h_x, h_y)
    print(f"h = E(({hex(h_x)}, {hex(h_y)})) -> {h}\n")

    # 3) Input COM commitment from args
    com_x, com_y = args.COMx, args.COMy
    COM = point_from_coords(com_x, com_y)
    print(f"Step 3: COM = E(({hex(com_x)}, {hex(com_y)})) -> {COM}\n")

    # 4) Nonce
    nonce = args.n
    print(f"Step 4: nonce = {hex(nonce)}\n")

    # 5) Input P commitment
    P_x, P_y = args.Px, args.Py
    P = point_from_coords(P_x, P_y)
    print(f"Step 5: P = E(({hex(P_x)}, {hex(P_y)})) -> {P}\n")

    # 6) Scalars v and w
    v, w = args.v, args.w
    print(f"Step 6: v = {hex(v)}, w = {hex(w)}\n")

# 7) Reconstruct raw 64-byte P = P.x || P.y
print("\nStep 7: Reconstruct raw P.x||P.y as hex")
# Convert each coordinate to 32-byte big-endian
px_bytes = int(P_x).to_bytes(32 , 'big')
py_bytes = int(P_y).to_bytes(32 , 'big')

# Concatenate
P_raw_bytes = px_bytes + py_bytes

# Sanity check length
assert len(P_raw_bytes) == 64

# Hex-encode (upper-case to match C notation)
P_raw_hex = P_raw_bytes.hex().upper()

print("P (hex) =", P_raw_hex)

# 8) Reconstruct raw 64-byte n
print("\nStep 8: Reconstruct raw 64-byte n as hex")

# Convert to 64-byte big-endian
nonce_bytes = int(nonce).to_bytes(64 , 'big')

# Hex-encode (upper-case to match C notation)
nonce_raw_hex = nonce_bytes.hex().upper()

print("n (hex) =", nonce_raw_hex)

# 9) Build the 128-byte preimage P||n
print("\nStep 9: Preimage (P || nonce) as hex:")
preimage_bytes = P_raw_bytes + nonce_bytes
assert len(preimage_bytes) == 128
print(preimage_bytes.hex().upper())

# 10) Compute α
print("\nStep 10: Compute α = H(P, n)")

# Compute SHA-256 over the preimage
hash_bytes = sha256(preimage_bytes).digest()
print("α (as hex) =", hash_bytes.hex().upper())

# Derive α from the hash
alpha = int.from_bytes(hash_bytes, 'big')
print("α (as integer) =", alpha)

# 11) Check if g^v*h^w=P*COM^α
print("\nStep 11: Check if g^v*h^w=P*COM^α")

# left-hand side: g^v * h^w  →  (v*g) + (w*h)
proof_left  = v*g + w*h
print("g^v * h^w =", proof_left)

proof_right = P + alpha*COM
print("P * COM^α =", proof_right)

# Check equality
if proof_left == proof_right:
    print("✅ Proof verifies: g^v·h^w = P·COM^α")
else:
    print("❌ Proof FAILED")

print("Computation complete")
