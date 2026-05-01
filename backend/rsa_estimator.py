import math


def estimate_rsa_security(modulus_bits: int) -> dict:
    """Estimate the security level of an RSA modulus via the GNFS.

    The General Number Field Sieve (GNFS) is the best known classical
    algorithm for factoring RSA moduli. Its asymptotic complexity is:

        L_N(1/3, (64/9)^(1/3)) =
            exp( (64/9)^(1/3) * (ln N)^(1/3) * (ln ln N)^(2/3) )

    where N = 2^k and k is the modulus bit-length. The security level lambda
    (in bits) is the base-2 logarithm of the GNFS runtime, less a small
    empirical o(1) correction calibrated against NIST/ECRYPT-II recommendations.
    """
    k = modulus_bits
    ln_N = k * math.log(2)
    ln_ln_N = math.log(ln_N)

    # (64/9)^(1/3) / ln(2) — converts natural-log GNFS cost to log2
    c = (64 / 9) ** (1 / 3) / math.log(2)

    # Asymptotic log2 cost
    log2_cost = c * (ln_N ** (1 / 3)) * (ln_ln_N ** (2 / 3))

    # Empirical o(1) correction: ~4.69 / ln(2) ~ 6.77
    # Calibrated so that 1024-bit → ~80, 2048-bit → ~112, 3072-bit → ~128
    correction = 4.69 / math.log(2)
    security_bits = log2_cost - correction
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
        "modulus_bits": k,
        "gnfs_log2_cost": round(log2_cost, 1),
        "security_level_bits": security_bits_rounded,
        "assessment": assessment,
        "hardness_assumption": "Integer Factorization (RSA Problem → Factoring → GNFS)",
        "explanation": (
            f"RSA security is based on the hardness of factoring large "
            f"composite integers N = p*q. The best known classical attack is "
            f"the General Number Field Sieve (GNFS) with sub-exponential "
            f"complexity L_N(1/3, (64/9)^(1/3)). "
            f"For a {k}-bit RSA modulus, the asymptotic GNFS log2 cost is "
            f"{log2_cost:.1f} bits. Applying the empirical o(1) correction "
            f"(-{correction:.1f} bits) calibrated to NIST/ECRYPT-II "
            f"recommendations yields an estimated security level of "
            f"lambda = {security_bits_rounded} bits ({assessment})."
        ),
    }
