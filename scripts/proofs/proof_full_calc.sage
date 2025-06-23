from hashlib import sha256

# Utility function to parse decimal or hex input
def parse_input(s):
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    else:
        return int(s, 10)

print("=== Zero Knowledge Proof Tool ===")

print("\n--- Enrollment phase ---")

# 1) Define curve
print("\nStep 1: Define secp256r1 curve (P-256)...")
p = 2^256 - 2^224 + 2^192 + 2^96 - 1
a = -3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
E = EllipticCurve(GF(p), [a, b])
print("Curve defined over F_p with equation: y^2 = x^3 + ax + b")

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

# 3) Scalars
print("\nStep 3: Enter scalars R1 and R2 (decimal or hex with 0x prefix)")
R1 = parse_input(input("Enter R1: "))
R2 = parse_input(input("Enter R2: "))
print("R1 =", R1)
print("R2 =", R2)

# 4) Compute COM commitment
print("\nStep 4: Compute COM = R1 * g + R2 * h")
COM = R1 * g + R2 * h
print("COM =", COM)

com_x, com_y = COM.xy()
print("\nResult (Affine Coordinates):")
print("COM.x =", com_x)
print("COM.y =", com_y)

print("\n--- Authentication phase ---")

# 5) Nonce
print("\nStep 5: Enter scalar nonce (decimal or hex with 0x prefix)")
nonce = parse_input(input("Enter nonce: "))

# 6) Random variables
print("\nStep 6: Enter scalars r and u (decimal or hex with 0x prefix)")
r = parse_input(input("Enter r: "))
u = parse_input(input("Enter u: "))
print("r =", r)
print("u =", u)

# 7) Compute P commitment
print("\nStep 7: Compute P = r * g + u * h")
P = r * g + u * h
print("P =", P)

P_x, P_y = P.xy()
print("\nResult (Affine Coordinates):")
print("P.x =", P_x)
print("P.y =", P_y)

# 8) Reconstruct raw 64-byte P = P.x || P.y
print("\nStep 8: Reconstruct raw P.x||P.y as hex")

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

# 9) Reconstruct raw 64-byte n
print("\nStep 9: Reconstruct raw 64-byte n as hex")

# Convert to 64-byte big-endian
nonce_bytes = int(nonce).to_bytes(64, 'big')

# Hex-encode (upper-case to match C notation)
nonce_raw_hex = nonce_bytes.hex().upper()

print("n (hex) =", nonce_raw_hex)

# 10) Build the 128-byte preimage P||n
print("\nStep 10: Preimage (P || nonce) as hex:")
preimage_bytes = P_raw_bytes + nonce_bytes
assert len(preimage_bytes) == 128
print(preimage_bytes.hex().upper())

# 11) Compute α
print("\nStep 11: Compute α = H(P, n)")

# Compute SHA-256 over the preimage
hash_bytes = sha256(preimage_bytes).digest()
print("α (as hex) =", hash_bytes.hex().upper())

# Derive α from the hash
alpha = int.from_bytes(hash_bytes, 'big')
print("α (as integer) =", alpha)

# 12) Compute αR1
print("\nStep 12: Compute αR1")
alpha_R1 = alpha * R1
print("αR1 =", alpha_R1)

# 13) Compute αR2
print("\nStep 13: Compute αR2")
alpha_R2 = alpha * R2
print("αR2 =", alpha_R2)

# 14) Compute v = r+αR1
print("\nStep 14: Compute v = r+αR1")
v = r + alpha_R1
print("v =", v)

# 15) Compute w = u+αR2
print("\nStep 15: Compute w = r+αR2")
w = u + alpha_R2
print("w =", w)

# 16) Check if g^v*h^w=P*COM^α
print("\nStep 16: Check if g^v*h^w=P*COM^α")

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
