# CrypEval: Provable Security Parameter Estimator

An interactive full-stack tool for analysing cryptographic hardness assumptions,
parameter trade-offs, and hardware brute-force resistance.  CrypEval provides
single-point security estimates and sweep-curve visualisations across
post-quantum (lattice), classical public-key, and symmetric/hash primitives.

---

## Core Features

### Post-Quantum / Lattice Cryptography
- **LWE (Learning With Errors)** — Core-SVP classical hardness via root Hermite
  factor δ → BKZ block-size β → security bits λ.  Based on the GapSVP → BDD →
  uSVP reduction chain.
- **CKKS / RLWE (Homomorphic Encryption)** — Ring-LWE security for the CKKS
  scheme.  Estimates λ from the ring dimension *N* and coefficient modulus *Q*,
  using the canonical embedding and the same δ → β → λ pipeline.

### Classical Public-Key Cryptography
- **RSA (Integer Factorisation)** — General Number Field Sieve (GNFS) complexity
  *L<sub>N</sub>(1/3, (64/9)<sup>1/3</sup>)*, calibrated against NIST /
  ECRYPT-II recommendations for key sizes from 1 024 to 15 360 bits.
- **ECC (Elliptic Curve / SECP256K1)** — Classical security via Pollard's rho
  (*λ* ≈ curve-bits / 2), with an explicit warning about Shor's algorithm
  reducing quantum security to 0 bits.

### Symmetric & Hash Brute-force
- **Multi-Adversary Hardware Simulator** — Five threat profiles spanning
  consumer CPUs to nation-state ASIC farms.
- **Five Hash Algorithms** — MD5, SHA-256, NTLM, WPA2 PBKDF2, and Argon2.
  Argon2 correctly models memory-hardness: GPU/ASIC rates are heavily
  bottlenecked by VRAM bandwidth.
- **Time-to-Crack Table** — Per-hardware estimates with emoji indicators
  (🔴 &lt; 1 day, 🟡 &lt; 1 year, 🟢 &gt; 1 year).

### Dynamic Trade-off Visualisation
- Interactive `st.line_chart` curves for LWE (*n* vs. *λ*) and CKKS
  (*log₂ Q* vs. *λ*), allowing users to explore how parameter choices affect
  security.

---

## Reproducible Build Instructions

These steps assume a Linux or WSL environment with Python 3.10+.

### 1. Clone & enter the project

```bash
git clone https://github.com/QinBei798/CrypEval.git
cd CrypEval
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the FastAPI backend (terminal 1)

```bash
cd backend
uvicorn main:app --host 127.0.0.1 --port 8000
```

The interactive API docs are now available at http://127.0.0.1:8000/docs.

### 5. Start the Streamlit frontend (terminal 2)

```bash
cd frontend
streamlit run app.py
```

The UI opens at http://localhost:8501.

---

## API Reference

All endpoints are `GET` and accept query parameters.  Responses are JSON.

| Endpoint | Parameters | Description |
|---|---|---|
| `/evaluate/lwe` | `n`, `q`, `sigma` | LWE single-point estimate |
| `/evaluate/lwe/curve` | `q`, `sigma` | Sweep *n* (256–1 024) → list of {x, y} |
| `/evaluate/ckks` | `N`, `Q`, `sigma` (default 3.2) | CKKS / RLWE single-point estimate |
| `/evaluate/ckks/curve` | `N`, `sigma` | Sweep *log₂ Q* (10–800) → list of {x, y} |
| `/evaluate/rsa` | `modulus_bits` | RSA GNFS estimate |
| `/evaluate/ecc` | `curve_bits` | ECC classical + quantum estimate |
| `/evaluate/bruteforce` | `algo`, `length`, `charset_size` | Multi-adversary brute-force table |

---

## Architecture & AI Workflow

```
CrypEval/
├── backend/
│   ├── main.py                  # FastAPI entry point & routing
│   ├── lwe_estimator.py         # LWE: δ → β → λ (Core-SVP)
│   ├── ckks_estimator.py        # CKKS / RLWE security
│   ├── rsa_estimator.py         # RSA GNFS complexity
│   ├── ecc_estimator.py         # ECC Pollard's rho + Shor warning
│   └── bruteforce_estimator.py  # Hardware brute-force simulator
├── frontend/
│   └── app.py                   # Streamlit UI (sidebar + metrics + charts)
├── requirements.txt
└── README.md
```

- **Backend** — FastAPI serving as a thin math-engine layer.  Each estimator is a
  pure-Python module that implements standard cryptographic hardness formulas
  without external crypto libraries.  This keeps the dependency footprint small
  and the code auditable.
- **Frontend** — Streamlit providing an interactive UI with dynamic sliders,
  metric cards, colour-coded security callouts, line charts, and expandable
  hardness-assumption explainers.  The frontend never performs cryptographic
  calculations; it delegates all estimation to the backend via REST calls.

### Agentic Workflow

This project was built using an **Agentic Workflow** (Claude Code) — an iterative,
plan-execute-verify development loop driven by natural-language instruction.
This stands in contrast to traditional cloud-deployed coding agents by keeping
execution local, version-controlled, and fully auditable.  Each phase
(scaffolding, LWE math, multi-primitive expansion, visualisation, brute-force
simulation) was entered into the conversation as a specification block and
implemented with human-in-the-loop review at every step.

---

## Cryptographic Hardness Summary

| Primitive | Hardness Assumption | Best Known Attack | Classical λ |
|---|---|---|---|
| LWE | GapSVP → BDD → uSVP | BKZ lattice reduction | 0.292 · β |
| CKKS / RLWE | Ring-LWE → Ideal-SVP | BKZ on canonical embedding | 0.292 · β |
| RSA | Integer Factorisation | GNFS | *L<sub>N</sub>(1/3, 1.923)* |
| ECC | ECDLP | Pollard's rho | *k*/2 |
| Brute-force | Key-space exhaustion | Exhaustive search | *log₂(S)* |
| Argon2 | Memory-hard KDF | Memory-bandwidth-bound search | *log₂(S / rate)* |

---

## License

This project is provided for educational and research purposes.  Always consult
current cryptographic standards (NIST, ECRYPT, BSI) before deploying real-world
cryptographic parameters.
