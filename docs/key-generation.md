# Sovereign Lattice – Threshold Key Generation

## Feldman Verifiable Secret Sharing (VSS)

Feldman VSS is the classical foundation for distributed key generation in the Execution Plane.

### Single-Dealer Flow

1. The dealer samples a random polynomial of degree $t-1$:
   $$f(x) = a_0 + a_1 x + \dots + a_{t-1} x^{t-1}, \quad a_0 = sk.$$

2. Public commitments are published:
   $$C_k = g^{a_k} \quad (k = 0,\dots,t-1).$$

3. Party $i$ receives the private share $s_i = f(i)$.

4. Verification equation (the algebraic heart):
   $$g^{s_i} \;\stackrel{?}{=}\; \prod_{k=0}^{t-1} C_k^{i^k}.$$
   If the check fails, a complaint is filed.

### Multi-Dealer Joint DKG

- Every validator acts as a dealer and runs Feldman VSS on its own random secret.
- After the complaint and disqualification phase, the final secret key is the sum of all surviving dealers’ secrets.
- The final group public key is the product of all surviving $C_0$ commitments.
- Each honest party holds a valid Shamir share of the joint secret, ready for threshold signing (FROST or threshold BLS).

This construction guarantees that no single party ever knows the full secret key, while any authorized quorum can produce signatures.
