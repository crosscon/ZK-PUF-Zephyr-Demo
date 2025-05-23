from hashlib import sha256

# Utility function to parse decimal or hex input
def parse_input(s):
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    else:
        return int(s, 10)

print("=== Zero Knowledge Verifier Proof Tool ===")

# 1) Define curve
print("\nStep 1: Define secp256r1 curve (P-256)...")
p = 2^256 - 2^224 + 2^192 + 2^96 - 1
a = -3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
E = EllipticCurve(GF(p), [a, b])
print("Curve defined over F_p with equation: y^2 = x^3 + ax + b\n")

# 2) Input base points
print("\nStep 2: Input coordinates for g and h (decimal or hex with 0x prefix)")

g_x = parse_input(input("Enter g_x: "))
g_y = parse_input(input("Enter g_y: "))
g = E((g_x, g_y))
print("g =", g)

h_x = parse_input(input("Enter h_x: "))
h_y = parse_input(input("Enter h_y: "))
h = E((h_x, h_y))
print("h =", h)

# 3) Input COM commitment
print("\nStep 3: Input coordinates for COM (decimal or hex with 0x prefix)")
com_x = parse_input(input("Enter COM_x: "))
com_y = parse_input(input("Enter COM_y: "))
COM = E((com_x, com_y))
print("COM =", COM)
# com_x, com_y = COM.xy()

# 4) Nonce
print("\nStep 4: Enter scalar nonce (decimal or hex with 0x prefix)")
nonce = parse_input(input("Enter nonce: "))

# 5) Input P commitment
print("\nStep 5: Input coordinates for COM (decimal or hex with 0x prefix)")
P_x = parse_input(input("Enter P_x: "))
P_y = parse_input(input("Enter P_y: "))
P = E((P_x, P_y))
print("P =", P)
# 9) Output result
# P_x, P_y = P.xy()

# 6) Scalars
print("\nStep 6: Enter scalars v and w (decimal or hex with 0x prefix)")
v = parse_input(input("Enter v: "))
w = parse_input(input("Enter w: "))
print("v =", v)
print("w =", w)

# 7) Reconstruct raw 64-byte P = P.x || P.y
print("\nStep 7: Reconstruct raw P.x||P.y as hex")
# Convert each coordinate to 32-byte big-endian
px_bytes = int(P_x).to_bytes(32, 'big')
py_bytes = int(P_y).to_bytes(32, 'big')

# Concatenate
P_raw_bytes = px_bytes + py_bytes

# Sanity check length
assert len(P_raw_bytes) == 64

# Hex-encode (upper-case to match C notation)
P_raw_hex = P_raw_bytes.hex().upper()

print("P (hex) =", P_raw_hex)

# 8) Reconstruct raw 16-byte n
print("\nStep 8: Reconstruct raw 16-byte n as hex")

# Convert to 16-byte big-endian
nonce_bytes = int(nonce).to_bytes(16, 'big')

# Hex-encode (upper-case to match C notation)
nonce_raw_hex = nonce_bytes.hex().upper()

print("n (hex) =", nonce_raw_hex)

# 9) Build the 80-byte preimage P||n
print("\nStep 9: Preimage (P || nonce) as hex:")
preimage_bytes = P_raw_bytes + nonce_bytes
assert len(preimage_bytes) == 80
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
