import math

# Per-algorithm hash rates for each hardware profile (hashes / second).
# Argon2 is memory-hard: GPU/ASIC parallelism is bottlenecked by VRAM bandwidth,
# so rates are orders of magnitude lower than compute-bound hashes.
HARDWARE_PROFILES = [
    {
        "name": "Intel i9 CPU (Baseline)",
        "rates": {
            "MD5 (Fast Hash)":                             5e9,
            "SHA-256 (Fast, ASIC-dominated)":              3e9,
            "NTLM (Extremely Fast, Windows AD)":           8e9,
            "WPA2 PBKDF2 (Slow Hash)":                    50e3,
            "Argon2 (Memory-Hard, Modern Standard)":       50,
        },
    },
    {
        "name": "RTX 4050 Laptop (Script Hacker)",
        "rates": {
            "MD5 (Fast Hash)":                            20e9,
            "SHA-256 (Fast, ASIC-dominated)":             12e9,
            "NTLM (Extremely Fast, Windows AD)":          40e9,
            "WPA2 PBKDF2 (Slow Hash)":                   150e3,
            "Argon2 (Memory-Hard, Modern Standard)":       80,
        },
    },
    {
        "name": "RTX 4090 Rig (Enthusiast)",
        "rates": {
            "MD5 (Fast Hash)":                           100e9,
            "SHA-256 (Fast, ASIC-dominated)":             70e9,
            "NTLM (Extremely Fast, Windows AD)":         250e9,
            "WPA2 PBKDF2 (Slow Hash)":                    2.5e6,
            "Argon2 (Memory-Hard, Modern Standard)":      200,
        },
    },
    {
        "name": "8× RTX 4090 Cluster (Syndicate)",
        "rates": {
            "MD5 (Fast Hash)":                           800e9,
            "SHA-256 (Fast, ASIC-dominated)":            560e9,
            "NTLM (Extremely Fast, Windows AD)":           2e12,
            "WPA2 PBKDF2 (Slow Hash)":                    20e6,
            "Argon2 (Memory-Hard, Modern Standard)":      1600,
        },
    },
    {
        "name": "ASIC / Cloud GPU Farm (Nation-State)",
        "rates": {
            "MD5 (Fast Hash)":                           100e12,
            "SHA-256 (Fast, ASIC-dominated)":            200e12,   # Bitcoin-grade SHA-256 ASICs
            "NTLM (Extremely Fast, Windows AD)":         500e12,
            "WPA2 PBKDF2 (Slow Hash)":                   100e6,
            "Argon2 (Memory-Hard, Modern Standard)":       10e3,    # still memory-bound
        },
    },
]

# Supported algorithms (keys must match the inner dicts above)
ALGO_FAMILIES = {algo: algo for algo in HARDWARE_PROFILES[0]["rates"]}


def _format_time(seconds: float) -> str:
    """Convert a time in seconds to a human-readable string."""
    if seconds < 60:
        return f"{seconds:.0f} secs"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} mins"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    elif seconds < 31_557_600:  # 1 year
        return f"{seconds / 86400:.1f} days"
    elif seconds < 100_000 * 31_557_600:
        return f"{seconds / 31_557_600:.1f} years"
    else:
        return "Unbreakable (>10⁵ yrs)"


def _format_hash_rate(rate: float) -> str:
    """Format a hash rate (h/s) into human-readable form."""
    if rate >= 1e12:
        return f"{rate / 1e12:.0f} TH/s"
    elif rate >= 1e9:
        return f"{rate / 1e9:.0f} GH/s"
    elif rate >= 1e6:
        return f"{rate / 1e6:.1f} MH/s"
    elif rate >= 1e3:
        return f"{rate / 1e3:.0f} kH/s"
    else:
        return f"{rate:.0f} H/s"


def _time_indicator(seconds: float) -> str:
    """Return an emoji indicator for the security of a given crack time."""
    if seconds < 86400:
        return "\U0001f534"        # red circle: cracked in < 1 day
    elif seconds < 31_557_600:
        return "\U0001f7e1"        # yellow circle: < 1 year
    else:
        return "\U0001f7e2"        # green circle: > 1 year


def estimate_bruteforce(algo: str, length: int, charset_size: int) -> dict:
    """Estimate brute-force cracking times across multiple hardware profiles.

    Args:
        algo: algorithm identifier (must be a key in ALGO_FAMILIES).
        length: password / key length.
        charset_size: size of the character set (e.g. 62 for alphanumeric).

    Returns:
        dict with search_space, algo_family, and a list of per-hardware results.
    """
    search_space = charset_size ** length

    results = []
    for profile in HARDWARE_PROFILES:
        rate = profile["rates"][algo]
        seconds = search_space / rate
        results.append({
            "actor": profile["name"],
            "hash_rate": _format_hash_rate(rate),
            "time_seconds": seconds,
            "time_display": _format_time(seconds),
            "indicator": _time_indicator(seconds),
        })

    # Determine algo family for display
    if "Argon2" in algo:
        family = "memory-hard"
    elif "PBKDF2" in algo:
        family = "slow iterative"
    else:
        family = "fast"

    return {
        "algo": algo,
        "algo_family": family,
        "length": length,
        "charset_size": charset_size,
        "search_space": search_space,
        "search_space_display": f"{search_space:.2e}",
        "results": results,
    }
