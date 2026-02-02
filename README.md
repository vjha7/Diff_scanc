## 1. Automated Differential Search with CryptoSMT

To search for differential characteristics using SMT solvers, we utilize the [CryptoSMT](https://github.com/kste/cryptosmt) framework.

**Setup:**

1. Clone the CryptoSMT repository:
```bash
git clone https://github.com/kste/cryptosmt

```

2. Copy `scanc_smt.py` from this repository into the `ciphers/` directory of the cloned CryptoSMT folder.
3. Register the new cipher by adding `scanc` to the main `cryptosmt.py` configuration.

**Execution:**

* To find a standard differential trail for 3 rounds:
```bash
python3 cryptosmt.py --cipher scanc --rounds 3 --wordsize 16

```


* To search for a **differential cluster** (multiple trails sharing the same input/output differences), use mode 4:
```bash
python3 cryptosmt.py --cipher scanc --mode 4 --rounds 3 --wordsize 16

```


*(Note: Change the number of rounds as needed).*



### 2. Empirical Verification

The file `diff_scanc.py` is a standalone script used to verify the theoretical trails found by the SMT solver.

**How it works:**

* It generates millions of plaintext pairs satisfying the input difference .
* It performs a full 3-round encryption using independent, random 16-bit round keys.
* It counts the occurrences where the output difference matches the target .
* Finally, it calculates the **experimental success probability** (), allowing for a direct comparison with the theoretical probability to ensure the trail's accuracy.

**To run the verification:**

```bash
python3 diff_scanc.py

```


