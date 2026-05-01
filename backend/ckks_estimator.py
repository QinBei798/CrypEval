import math
from lwe_estimator import _delta_to_bkz_block_size


def estimate_ckks_security(N: int, Q: int, sigma: float = 3.2) -> dict:
    """Estimate the security level of CKKS / RLWE parameters (N, Q, sigma).

    CKKS operates in the ring R_Q = Z_Q[X] / (X^N + 1). The security reduces
    to the Ring-LWE problem, which in turn reduces to the approximate Shortest
    Vector Problem (SVP) on ideal lattices.

    The primal lattice attack on RLWE is structurally similar to standard LWE:
        delta = (Q / sigma) ^ (1/N)

    where N is the ring dimension and Q is the coefficient modulus (the
    product of all RNS primes in the modulus chain).
    """
    # Root Hermite factor for RLWE: delta = (Q / sigma) ^ (1/N)
    delta = (Q / sigma) ** (1.0 / N)

    beta = _delta_to_bkz_block_size(delta)
    security_bits = 0.292 * beta
    security_bits_rounded = round(security_bits, 1)

    if security_bits < 80:
        assessment = "insecure (below 80-bit)"
    elif security_bits < 112:
        assessment = "weak (below 112-bit)"
    elif security_bits < 128:
        assessment = "acceptable (near 128-bit)"
    elif security_bits < 192:
        assessment = "strong (128-bit or higher)"
    else:
        assessment = "very strong (192-bit or higher)"

    return {
        "N": N,
        "Q": Q,
        "sigma": sigma,
        "root_hermite_factor": round(delta, 6),
        "estimated_bkz_block_size": round(beta, 1),
        "security_level_bits": security_bits_rounded,
        "assessment": assessment,
        "hardness_assumption": "Ring-LWE → Ideal-SVP (via canonical embedding)",
        "explanation": (
            f"CKKS / RLWE security reduces to the Ring-LWE problem over the "
            f"cyclotomic ring Z_Q[X] / (X^{N} + 1). The best known classical "
            f"attack applies BKZ lattice reduction to the primal uSVP instance "
            f"constructed from the canonical embedding. "
            f"Given N={N}, Q={Q}, sigma={sigma}, the attacker must achieve a "
            f"root Hermite factor delta = {delta:.6f}, which requires a BKZ "
            f"block size of beta = {beta:.0f}. Under the core-SVP model, "
            f"the classical security is estimated at lambda = {security_bits_rounded} bits "
            f"({assessment})."
        ),
    }
