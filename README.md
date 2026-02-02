Differential Cryptanalysis of Scan-C

This repository contains the experimental verification of a 3-round differential trail and its success probability for the Scan-C block cipher.

Project Overview
The primary goal of this project is to validate the theoretical differential characteristics of Scan-C through empirical simulation. By analyzing a high volume of plaintext pairs, we demonstrate that the observed propagation of differences aligns with predicted mathematical models.

Methodology
To verify the 3-round differential trail, the following process was implemented:

Pair Generation: A large sample of plaintext pairs was generated, specifically satisfying the chosen input difference (ΔP).

Round Key Simulation: Each round of the 3-round Scan-C encryption was assigned a unique, randomly generated 16-bit key to ensure the results are key-independent.

Encryption: Both plaintexts in each pair were encrypted through 3 rounds of the cipher.

Difference Analysis: The output difference (ΔC) of each ciphertext pair was calculated and compared against the target output differential.

Probability Calculation: The empirical probability was derived by calculating the ratio of "hits" (pairs matching the target output difference) to the total number of trials.

Key Findings
Empirical Success: The experimental results confirm the validity of the differential trail.

Theoretical Alignment: The measured empirical probability closely matches the theoretical probability, providing strong evidence for the correctness of the cryptanalytic model.
