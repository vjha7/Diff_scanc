import random
import time
import math

# --- S-Box and Permutation Definitions ---
sP = [0x3, 0xF, 0xE, 0x0, 0x5, 0x4, 0xB, 0xC, 0xD, 0xA, 0x9, 0x6, 0x7, 0x8, 0x2, 0x1]
sQ = [0x0, 0x8, 0x6, 0xD, 0x5, 0xF, 0x7, 0xC, 0x4, 0xE, 0x2, 0x3, 0x9, 0x1, 0xB, 0xA]
PERM_MAP = [0, 1, 4, 5, 2, 3, 8, 9, 6, 7, 12, 13, 10, 11, 14, 15]

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

def F_function(val):
    # Standard 3-layer F-function structure
    val = apply_sbox_layer(val, [sP, sQ, sP, sQ])
    val = apply_permutation(val)
    val = apply_sbox_layer(val, [sQ, sP, sQ, sP])
    val = apply_permutation(val)
    val = apply_sbox_layer(val, [sP, sQ, sP, sQ])
    return val

# --  Scan-C Round Encryption --
def encrypt_round(p1, p2, p3, p4, k1):
    # R1-1 = P1-1 XNOR K1
    r_1_1 = ~(p1 ^ k1) & 0xFFFF
    ef_l1 = F_function(r_1_1)
    
    # R1-2 = Ef_l1 ^ P1-3
    r_1_2 = ef_l1 ^ p3
    
    # R1-4 = P1-4 XNOR K1
    r_1_4 = ~(p4 ^ k1) & 0xFFFF
    ef_r1 = F_function(r_1_4)
    
    # R1-3 = Ef_r1 ^ P1-2
    r_1_3 = ef_r1 ^ p2
    
    # State update for next round (P2 definitions)
    new_p1 = r_1_2
    new_p2 = r_1_1
    new_p3 = r_1_4
    new_p4 = r_1_3

    return new_p1, new_p2, new_p3, new_p4

def encrypt_block(p1, p2, p3, p4, round_keys):
    for r_key in round_keys:
        p1, p2, p3, p4 = encrypt_round(p1, p2, p3, p4, r_key)
    return p1, p2, p3, p4

def verify_trail():
    # Input differences
    diff_in = (0x000F, 0x00D0, 0x00B0, 0x0000)
    # Target output differences
    target_diffs = (0x00F0, 0x000F, 0x0000, 0x00D0)

    round_keys = [random.getrandbits(16) for _ in range(3)]
    N_TRIALS = 20_000_000
    hits = 0
    start_time = time.time()

    print(f"Starting verification for {N_TRIALS} pairs...")

    for i in range(1, N_TRIALS + 1):
        a = [random.getrandbits(16) for _ in range(4)]
        b = [a[j] ^ diff_in[j] for j in range(4)]

        enc_a = encrypt_block(*a, round_keys)
        enc_b = encrypt_block(*b, round_keys)

        out_diffs = tuple(enc_a[j] ^ enc_b[j] for j in range(4))

        if out_diffs == target_diffs:
            hits += 1
            print(f"[*] Match found at iteration {i}!")

        if i % 1_000_000 == 0:
            elapsed = time.time() - start_time
            print(f"Processed {i} pairs. Hits: {hits}. Time: {elapsed:.2f}s")

    print("\n--- Final Results ---")
    print(f"Total Hits: {hits}")
    if hits > 0:
        prob = math.log2(hits/N_TRIALS)
        print(f"Experimental Probability: 2^{prob:.2f}")

if __name__ == "__main__":
    verify_trail()
