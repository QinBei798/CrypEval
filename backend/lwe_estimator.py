import math


def _delta_to_bkz_block_size(delta: float) -> float:
    """Solve for BKZ block size beta given root Hermite factor delta.

    Uses the standard BKZ root Hermite factor formula:
        delta = ((pi*beta)^(1/beta) * beta / (2*pi*e)) ^ (1/(2*beta - 2))

    Rearranged as f(beta) = 0:
        2*(beta-1)*log(delta) - log(beta) + log(2*pi*e) - log(pi*beta)/beta = 0

    The function f is non-monotonic (positive → negative → positive).  The first
    root is an artefact of the approximation at small beta; we need the upper
    (physically meaningful) root found to the right of the minimum of f.
    """
    if delta <= 1.0:
        return float("inf")

    target = math.log(delta)
    log_2pie = math.log(2 * math.pi * math.e)

    def _f(b: float) -> float:
        return 2 * (b - 1) * target - math.log(b) + log_2pie - math.log(math.pi * b) / b

    # Minimum of f is near beta ~ 1 / (2 * log(delta)).  Start search there.
    beta_min = 1.0 / (2.0 * target)

    if _f(beta_min) > 0:
        return 2.0  # delta too large for any BKZ beta, effectively broken

    # Find upper bound (f > 0) by doubling upward from beta_min
    hi = max(beta_min, 4.0)
    while _f(hi) < 0 and hi < 10_000_000:
        hi *= 2

    if _f(hi) < 0:
        return float("inf")  # no upper root found (should not happen)

    lo = beta_min
    for _ in range(80):
        mid = (lo + hi) / 2
        fm = _f(mid)
        if abs(fm) < 1e-10:
            return mid
        if fm < 0:
            lo = mid
        else:
            hi = mid

    return (lo + hi) / 2


def estimate_lwe_security(n: int, q: int, sigma: float) -> dict:
    """Estimate the security level of LWE parameters (n, q, sigma).

    Uses the root Hermite factor approach based on the primal lattice attack.
    The LWE problem reduces to GapSVP (Shortest Vector Problem) on lattices.
    The best known attack applies the BKZ lattice reduction algorithm.

    Returns a dict with the root Hermite factor, estimated BKZ block size,
    security level in bits, and a human-readable explanation.
    """
    # Root Hermite factor: delta = (q / sigma) ^ (1/n)
    # This is the standard rule-of-thumb for the distinguishing attack on LWE.
    delta = (q / sigma) ** (1.0 / n)

    # Convert to BKZ block size and then to security bits
    beta = _delta_to_bkz_block_size(delta)

    # Core-SVP classical hardness: lambda = 0.292 * beta
    # (quantum would use 0.265 * beta)
    security_bits = 0.292 * beta
    security_bits_rounded = round(security_bits, 1)

    # Qualitative assessment
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
        "n": n,
        "q": q,
        "sigma": sigma,
        "root_hermite_factor": round(delta, 6),
        "estimated_bkz_block_size": round(beta, 1),
        "security_level_bits": security_bits_rounded,
        "assessment": assessment,
        "hardness_assumption": "GapSVP (via LWE → BDD → uSVP reduction)",
        "explanation": (
            f"The LWE problem reduces to the GapSVP (Shortest Vector Problem) "
            f"on lattices. The best known classical attack applies the BKZ "
            f"lattice reduction algorithm to the primal uSVP instance. "
            f"Given n={n}, q={q}, sigma={sigma}, the attacker must achieve a "
            f"root Hermite factor delta = {delta:.6f}, which requires a BKZ "
            f"block size of beta = {beta:.0f}. Under the core-SVP model, "
            f"the classical security is estimated at lambda = {security_bits_rounded} bits "
            f"({assessment})."
        ),
    }
