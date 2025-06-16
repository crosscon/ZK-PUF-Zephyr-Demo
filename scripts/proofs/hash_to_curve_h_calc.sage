"""
Hash-to-Curve Point Generation Tool (P-256)
`h` is generated deterministically from a string
"""

import argparse
from hashlib import sha256

def parse_input(s):
    return s

parser = argparse.ArgumentParser(
    description="Hash-to-Curve Point Generation Tool (P-256)"
)
parser.add_argument(
    '-i', '--interactive',
    action='store_true',
    help='Run in interactive mode (will prompt for each parameter).'
)
parser.add_argument('-s', type=parse_input, help='string from which h will be generated')

args = parser.parse_args()

# Constant byte string from which the generator h will be deterministically derived
# label = b"constant_string_generator"

if args.interactive:
    print("=== Hash-to-Curve Point Generation Tool (Interactive Mode) ===\n")

    print("Input string for h generation")
    label_str = input("Enter string: ")

else:
    # Non-interactive: ensure all parameters are provided
    required_fields = ['s']
    missing = [f for f in required_fields if getattr(args, f) is None]
    if missing:
        parser.error(f"In non-interactive mode, the following arguments are required: {', '.join('-' + m for m in missing)}")
    label_str = args.s

# 1) Define curve
p = 2^256 - 2^224 + 2^192 + 2^96 - 1
a = -3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
E = EllipticCurve(GF(p), [a, b])
print("Curve defined over F_p with equation: y^2 = x^3 + ax + b\n")

# Max attempts before giving up (not all hashes yield a valid x-coordinate)
MAX_HASH_TRIES = 1000

label = label_str.encode('utf-8')

def find_h_point():
    for ctr in range(MAX_HASH_TRIES):
        # 4-byte big-endian counter
        ctr_bytes = ctr.to_bytes(4, 'big')

        # Construct 64-byte buffer: label (max 60 bytes) + counter
        input_bytes = bytearray(64)
        input_bytes[:min(60, len(label))] = label[:60]
        input_bytes[60:] = ctr_bytes

        # Compute SHA-256 hash of input
        digest = sha256(input_bytes).digest()

        # Convert digest to candidate x-coordinate mod p
        x = int.from_bytes(digest, 'big') % p

        print(f"Candidate for h_x at index {ctr} = {x} \n")

        # Check if x is a valid x-coordinate on the curve
        if E.is_x_coord(x):
            # Get both possible (x, y) points
            pts = E.lift_x(x, all=True)
            for pt in pts:
                y = pt[1]
                # Choose the one with even y
                if Integer(y) % 2 == 0:
                    print(f"Found point at counter = {ctr} with even y:")
                    return pt
            # Fallback to return the first if none were even
            return pts[0]

    print("Failed to find a valid point within MAX_HASH_TRIES")
    return None

# Run and print the point coordinates in decimal
h_point = find_h_point()
if h_point:
    x_dec = Integer(h_point[0])
    y_dec = Integer(h_point[1])
    print("h.x =", x_dec)
    print("h.y =", y_dec)
