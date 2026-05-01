def estimate_ecc_security(curve_bits: int) -> dict:
    """Estimate the security level of an elliptic curve key size.

    Classical security is based on the Elliptic Curve Discrete Logarithm
    Problem (ECDLP). The best known classical attack is Pollard's rho
    algorithm, which runs in O(sqrt(n)) time where n is the order of the
    subgroup. This gives an effective security of roughly curve_bits / 2.

    Quantum computers running Shor's algorithm can solve the ECDLP in
    polynomial time, completely breaking ECC security regardless of curve
    size. The quantum security level is therefore effectively 0 bits for
    any practical curve size.
    """
    # Classical: Pollard's rho — sqrt of group order
    classical_bits = curve_bits / 2
    classical_rounded = round(classical_bits, 1)

    # Qualitative assessment based on classical security
    if classical_bits < 80:
        assessment = "insecure (below 80-bit)"
    elif classical_bits < 112:
        assessment = "weak (below 112-bit)"
    elif classical_bits < 128:
        assessment = "acceptable (near 128-bit)"
    elif classical_bits < 192:
        assessment = "strong (128-bit or higher)"
    else:
        assessment = "very strong (192-bit or higher)"

    return {
        "curve_bits": curve_bits,
        "security_level_bits": classical_rounded,
        "classical_security_bits": classical_rounded,
        "attack_complexity": f"O(2^{classical_rounded}) via Pollard's rho",
        "quantum_security_bits": 0.0,
        "quantum_vulnerable": True,
        "assessment": assessment,
        "hardness_assumption": "ECDLP (Elliptic Curve Discrete Logarithm Problem)",
        "explanation": (
            f"The security of ECC relies on the hardness of the Elliptic Curve "
            f"Discrete Logarithm Problem (ECDLP). For a {curve_bits}-bit curve "
            f"(e.g., SECP256K1 or P-{curve_bits // 2}), the best known "
            f"**classical** attack is Pollard's rho algorithm with complexity "
            f"O(2^{classical_rounded}), yielding an estimated classical security "
            f"level of lambda = {classical_rounded} bits ({assessment}). "
            f"However, **Shor's quantum algorithm** solves the ECDLP in "
            f"polynomial time on a sufficiently large fault-tolerant quantum "
            f"computer, reducing the quantum security level to effectively "
            f"0 bits. ECC provides no post-quantum security whatsoever."
        ),
    }
