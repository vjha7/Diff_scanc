import random
import time
import math


# S-Box Definitions 
sP = [0x3, 0xF, 0xE, 0x0, 0x5, 0x4, 0xB, 0xC,
      0xD, 0xA, 0x9, 0x6, 0x7, 0x8, 0x2, 0x1]

sQ = [0x0, 0x8, 0x6, 0xD, 0x5, 0xF, 0x7, 0xC,
      0x4, 0xE, 0x2, 0x3, 0x9, 0x1, 0xB, 0xA]

#  Permutation Map 
PERM_MAP = [0, 1, 4, 5, 2, 3, 8, 9, 6, 7, 12, 13, 10, 11, 14, 15]

_F_TABLE3 = [1, 1, 0, 0, 0, 0, 1, 1,
             0, 1, 1, 0, 0, 1, 0, 1,
             1, 0, 0, 0, 1, 1, 0, 1,
             1, 0, 1, 1, 0, 0, 1, 0]


# Key Schedule

class SCAN_C_KeySchedule:

    def __init__(self, session_key_185bit):
        assert len(session_key_185bit) == 185,
        sk = session_key_185bit

        # Layer 2: MUX selection bits  sk_0 .. sk_24
        self.sk_mux = list(sk[0:25])

        # Layer 1: LFSR initial vectors
        self.lfsr_89 = list(sk[25:114])    # sk_25  .. sk_113
        self.lfsr_37 = list(sk[114:151])   # sk_114 .. sk_150
        self.lfsr_34 = list(sk[151:185])   # sk_151 .. sk_184

    def _clock_lfsrs(self):
        # 34-bit LFSR (12 taps)
        fb34 = (self.lfsr_34[33] ^ self.lfsr_34[26] ^ self.lfsr_34[25] ^
                self.lfsr_34[22] ^ self.lfsr_34[21] ^ self.lfsr_34[20] ^
                self.lfsr_34[19] ^ self.lfsr_34[12] ^ self.lfsr_34[10] ^
                self.lfsr_34[5]  ^ self.lfsr_34[1]  ^ self.lfsr_34[0])
        self.lfsr_34 = [fb34] + self.lfsr_34[:-1]

        # 37-bit LFSR (6 taps)
        fb37 = (self.lfsr_37[36] ^ self.lfsr_37[32] ^ self.lfsr_37[30] ^
                self.lfsr_37[29] ^ self.lfsr_37[20] ^ self.lfsr_37[0])
        self.lfsr_37 = [fb37] + self.lfsr_37[:-1]

        # 89-bit LFSR (7 taps)
        fb89 = (self.lfsr_89[88] ^ self.lfsr_89[82] ^ self.lfsr_89[79] ^
                self.lfsr_89[54] ^ self.lfsr_89[41] ^ self.lfsr_89[38] ^
                self.lfsr_89[0])
        self.lfsr_89 = [fb89] + self.lfsr_89[:-1]

    @staticmethod
    def _nonlinear_f(x1, x2, x3, x4, x5):
        idx = (x5 << 4) | (x4 << 3) | (x3 << 2) | (x2 << 1) | x1
        return _F_TABLE3[idx]

    def _generate_bit(self):
        pool = self.lfsr_34 + self.lfsr_37 + self.lfsr_89
        xs = []
        for m in range(5):
            sel = 0
            for b in self.sk_mux[m * 5:(m + 1) * 5]:
                sel = (sel << 1) | b
            group = pool[m * 32:(m + 1) * 32]
            xs.append(group[sel % 32])

        out = self._nonlinear_f(*xs)
        self._clock_lfsrs()
        return out

    def get_round_keys(self, num_rounds=3):
        keys = []
        for _ in range(num_rounds):
            rk = 0
            for bit_pos in range(16):
                rk |= (self._generate_bit() << bit_pos)
            keys.append(rk)
        return keys

# F-Function
def _apply_sbox_layer(val, boxes):
    res = 0
    for i in range(4):
        nibble = (val >> (i * 4)) & 0xF
        res |= (boxes[i][nibble] << (i * 4))
    return res

def _apply_permutation(val):
    res = 0
    for out_bit in range(16):
        res |= (((val >> PERM_MAP[out_bit]) & 1) << out_bit)
    return res

def F_function(val):
    val = _apply_sbox_layer(val, [sP, sQ, sP, sQ])
    val = _apply_permutation(val)
    val = _apply_sbox_layer(val, [sQ, sP, sQ, sP])
    val = _apply_permutation(val)
    val = _apply_sbox_layer(val, [sP, sQ, sP, sQ])
    return val


# Encryption

def encrypt_round(p1, p2, p3, p4, key, mode='XNOR'):
    if mode == 'XNOR':
        r1 = (~(p1 ^ key)) & 0xFFFF
        r4 = (~(p4 ^ key)) & 0xFFFF
    else:  # XOR  (special-case variant, paper page 10)
        r1 = p1 ^ key
        r4 = p4 ^ key

    efl = F_function(r1)
    efr = F_function(r4)

    r2 = efl ^ p3
    r3 = efr ^ p2

    # Swap for next round
    return r2, r1, r4, r3

def encrypt_block(p1, p2, p3, p4, keys, mode='XNOR'):
    for k in keys:
        p1, p2, p3, p4 = encrypt_round(p1, p2, p3, p4, k, mode)
    return p1, p2, p3, p4

def validate_nonlinear_function():
    print("Self-Test")
    fails = []
    for i in range(32):
        x5 = (i >> 4) & 1
        x4 = (i >> 3) & 1
        x3 = (i >> 2) & 1
        x2 = (i >> 1) & 1
        x1 = (i >> 0) & 1
        got = SCAN_C_KeySchedule._nonlinear_f(x1, x2, x3, x4, x5)
        exp = _F_TABLE3[i]
        if got != exp:
            fails.append((i + 1, x5, x4, x3, x2, x1, got, exp))

    if not fails:
        print("  All 32 rows PASSED.\n")
        return True
    else:
        for row, x5, x4, x3, x2, x1, got, exp in fails:
            print(f"  FAIL row {row:2d}: "
                  f"X5={x5} X4={x4} X3={x3} X2={x2} X1={x1} "
                  f"got={got} expected={exp}")
        print()
        return False



def verify_trail(seed=None):
    diff_in  = (0x000F, 0x00D0, 0x00B0, 0x0000)
    diff_out = (0x00F0, 0x000F, 0x0000, 0x00D0)

    if seed is not None:
        random.seed(seed)

    # Derive round keys from the key schedule
    session_key = [random.randint(0, 1) for _ in range(185)]
    ks = SCAN_C_KeySchedule(session_key)
    round_keys = ks.get_round_keys(num_rounds=3)

    N_TRIALS = 20_000_000
    hits = 0

    print("3-Round Differential Trail Verification")
    print(f"Input  diffs : {[hex(d) for d in diff_in]}")
    print(f"Output diffs : {[hex(d) for d in diff_out]}")
    print(f"Round keys   : {[hex(k) for k in round_keys]}")
    print(f"Trials       : {N_TRIALS:,}\n")

    start = time.time()

    for i in range(1, N_TRIALS + 1):
        # Random plaintext pair with fixed input difference
        a = (random.getrandbits(16), random.getrandbits(16),
             random.getrandbits(16), random.getrandbits(16))
        b = tuple(a[j] ^ diff_in[j] for j in range(4))

        enc_a = encrypt_block(*a, keys=round_keys, mode='XNOR')
        enc_b = encrypt_block(*b, keys=round_keys, mode='XNOR')

        if tuple(enc_a[j] ^ enc_b[j] for j in range(4)) == diff_out:
            hits += 1
            print(f"  [HIT] Match found at iteration {i:,}!")

        if i % 2_000_000 == 0:
            elapsed = time.time() - start
            eta = (N_TRIALS - i) / (i / elapsed)
            print(f"  {i:,}/{N_TRIALS:,} | Hits: {hits} | "
                  f"Elapsed: {elapsed:.1f}s | ETA: {eta:.1f}s")

    elapsed = time.time() - start
    print("\n Results")
    print(f"Total trials : {N_TRIALS:,}")
    print(f"Total hits   : {hits}")
    if hits > 0:
        print(f"Observed prob: 2^-{math.log2(N_TRIALS / hits):.2f}")
    else:
        print("No hits (2^-24 trail needs ~50M+ trials for a reliable estimate).")
    print(f"Total time   : {elapsed:.2f}s")


if __name__ == "__main__":
    ok = validate_nonlinear_function()
    if not ok:
        print("ERROR: nonlinear function mismatch \n")

    verify_trail(seed=42)   # remove seed= for a fresh random run
