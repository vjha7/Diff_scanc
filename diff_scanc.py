import random
import time
import math

# --- S-Box Definitions ---
sP = [0x3, 0xF, 0xE, 0x0, 0x5, 0x4, 0xB, 0xC,
      0xD, 0xA, 0x9, 0x6, 0x7, 0x8, 0x2, 0x1]

sQ = [0x0, 0x8, 0x6, 0xD, 0x5, 0xF, 0x7, 0xC,
      0x4, 0xE, 0x2, 0x3, 0x9, 0x1, 0xB, 0xA]

# --- Permutation Map ---
PERM_MAP = [0, 1, 4, 5, 2, 3, 8, 9, 6, 7, 12, 13, 10, 11, 14, 15]

# ---- Substitution and permutation ---
def apply_sbox_layer(val, sbox_list):
    res = 0
    for i in range(4):
        nibble = (val >> (i * 4)) & 0xF
        out_nib = sbox_list[i][nibble]
        res |= (out_nib << (i * 4))
    return res

def apply_permutation(val):
    res = 0
    for out_bit in range(16):
        in_bit = PERM_MAP[out_bit]
        bit = (val >> in_bit) & 1
        res |= (bit << out_bit)
    return res

# --- F function (combination of all 12 S-boxes and permutation layer) ---
def F_function(val):
    # --- Layer 1 --
    val = apply_sbox_layer(val, [sP, sQ, sP, sQ])
    val = apply_permutation(val)

    # --- Layer 2 --
    val = apply_sbox_layer(val, [sQ, sP, sQ, sP])
    val = apply_permutation(val)

    # --- Layer 3 ---
    val = apply_sbox_layer(val, [sP, sQ, sP, sQ])

    return val

# -- Scan-C round encryption with Key Mixing --
def encrypt_round(p1, p2, p3, p4, key, mode='XNOR'):
    if mode == 'XNOR':
        # XNOR mixing
        k_p1 = ~(p1 ^ key) & 0xFFFF
        k_p4 = ~(p4 ^ key) & 0xFFFF
    else:
        # XOR mixing
        k_p1 = p1 ^ key
        k_p4 = p4 ^ key

    ef_l = F_function(k_p1)
    ef_r = F_function(k_p4)

    new_p1 = ef_l ^ p3
    new_p2 = p1
    new_p3 = p4
    new_p4 = ef_r ^ p2

    return new_p1, new_p2, new_p3, new_p4

# ---- 3 round encryption ----
def encrypt_block(p1, p2, p3, p4, keys, mode='XNOR'):
    for i in range(len(keys)):
        p1, p2, p3, p4 = encrypt_round(p1, p2, p3, p4, keys[i], mode)
    return p1, p2, p3, p4

# - Verification Logic ---

def verify_trail(mode='XNOR'):
    diff_in_p1 = 0x000F
    diff_in_p2 = 0x00D0
    diff_in_p3 = 0x00B0
    diff_in_p4 = 0x0000

    diff_out_p1_target = 0x00F0
    diff_out_p2_target = 0x000F
    diff_out_p3_target = 0x0000
    diff_out_p4_target = 0x00D0

    N_TRIALS = 20_000_000
    hits = 0

    print(f"--- Verification Mode: {mode} ---")
    print(f"Starting verification for {N_TRIALS} pairs...")
    print(f"Theoretical Trail Probability: 2^-24 (~1 in 16.7M)")

    start_time = time.time()

    for i in range(1, N_TRIALS + 1):
        a_p1 = random.getrandbits(16)
        a_p2 = random.getrandbits(16)
        a_p3 = random.getrandbits(16)
        a_p4 = random.getrandbits(16)

        b_p1 = a_p1 ^ diff_in_p1
        b_p2 = a_p2 ^ diff_in_p2
        b_p3 = a_p3 ^ diff_in_p3
        b_p4 = a_p4 ^ diff_in_p4

        round_keys = [random.getrandbits(16) for _ in range(3)]

        enc_a = encrypt_block(a_p1, a_p2, a_p3, a_p4, round_keys, mode=mode)
        enc_b = encrypt_block(b_p1, b_p2, b_p3, b_p4, round_keys, mode=mode)

        d_out_p1 = enc_a[0] ^ enc_b[0]
        d_out_p2 = enc_a[1] ^ enc_b[1]
        d_out_p3 = enc_a[2] ^ enc_b[2]
        d_out_p4 = enc_a[3] ^ enc_b[3]

        if (d_out_p1 == diff_out_p1_target and
            d_out_p2 == diff_out_p2_target and
            d_out_p3 == diff_out_p3_target and
            d_out_p4 == diff_out_p4_target):
            hits += 1
            print(f"[*] Match found at iteration {i}!")

        if i % 1_000_000 == 0:
            elapsed = time.time() - start_time
            print(f"Processed {i}M pairs. Hits: {hits}. Elapsed: {elapsed:.2f}s")

    print("\n--- Final Results ---")
    print(f"Total Trials: {N_TRIALS}")
    print(f"Total Hits: {hits}")
    if hits > 0:
        emp_prob = -math.log2(hits / N_TRIALS)
        print(f"Experimental Probability: 2^-{emp_prob:.2f}")
    else:
        print("No hits found in this sample.")

if __name__ == "__main__":
    # You can switch between 'XNOR' and 'XOR' to prove equivalence
    verify_trail(mode='XNOR')
