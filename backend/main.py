from fastapi import FastAPI, Query
from lwe_estimator import estimate_lwe_security
from ckks_estimator import estimate_ckks_security
from rsa_estimator import estimate_rsa_security
from ecc_estimator import estimate_ecc_security
from bruteforce_estimator import estimate_bruteforce, ALGO_FAMILIES

app = FastAPI(title="CrypEval", version="0.3.0")


@app.get("/evaluate/lwe")
def evaluate_lwe(n: int = Query(..., description="Lattice dimension"),
                 q: int = Query(..., description="Modulus"),
                 sigma: float = Query(..., description="Noise standard deviation")):
    """Estimate security of standard LWE parameters (n, q, sigma)."""
    return estimate_lwe_security(n=n, q=q, sigma=sigma)


@app.get("/evaluate/ckks")
def evaluate_ckks(N: int = Query(..., description="Ring dimension (power of two)"),
                  Q: int = Query(..., description="Coefficient modulus"),
                  sigma: float = Query(3.2, description="Noise standard deviation (default CKKS)")):
    """Estimate security of CKKS / RLWE parameters (N, Q, sigma)."""
    return estimate_ckks_security(N=N, Q=Q, sigma=sigma)


@app.get("/evaluate/rsa")
def evaluate_rsa(modulus_bits: int = Query(..., description="RSA modulus size in bits")):
    """Estimate security of an RSA modulus via GNFS complexity."""
    return estimate_rsa_security(modulus_bits=modulus_bits)


@app.get("/evaluate/ecc")
def evaluate_ecc(curve_bits: int = Query(..., description="Elliptic curve size in bits (e.g., 256 for P-256/SECP256K1)")):
    """Estimate classical and quantum security of an elliptic curve."""
    return estimate_ecc_security(curve_bits=curve_bits)


@app.get("/evaluate/bruteforce")
def evaluate_bruteforce(algo: str = Query(..., description="Algorithm name (e.g., 'MD5 (Fast Hash)')"),
                        length: int = Query(..., ge=1, description="Password / key length"),
                        charset_size: int = Query(..., ge=1, description="Character set size (e.g., 62)")):
    """Estimate brute-force cracking times across hardware profiles."""
    if algo not in ALGO_FAMILIES:
        from fastapi import HTTPException
        raise HTTPException(400, f"Unknown algo. Choose from: {list(ALGO_FAMILIES.keys())}")
    return estimate_bruteforce(algo=algo, length=length, charset_size=charset_size)


@app.get("/evaluate/lwe/curve")
def evaluate_lwe_curve(q: int = Query(..., description="Modulus"),
                       sigma: float = Query(..., description="Noise standard deviation")):
    """Generate a trade-off curve: security lambda vs lattice dimension n."""
    points = []
    for n in range(256, 1024 + 1, 64):
        result = estimate_lwe_security(n=n, q=q, sigma=sigma)
        points.append({"x": n, "y": result["security_level_bits"]})
    return points


@app.get("/evaluate/ckks/curve")
def evaluate_ckks_curve(N: int = Query(..., description="Ring dimension"),
                        sigma: float = Query(3.2, description="Noise standard deviation")):
    """Generate a trade-off curve: security lambda vs log2 coefficient modulus."""
    points = []
    for log2_Q in range(10, 800 + 1, 20):
        Q = 2 ** log2_Q
        result = estimate_ckks_security(N=N, Q=Q, sigma=sigma)
        points.append({"x": log2_Q, "y": result["security_level_bits"]})
    return points
