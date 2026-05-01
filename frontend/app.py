import streamlit as st
import requests

BACKEND_BASE = "http://127.0.0.1:8000"

st.set_page_config(page_title="CrypEval: LWE Security Estimator", layout="wide")
st.title("CrypEval: Provable Security Parameter Estimator")

# ---- Sidebar ----
with st.sidebar:
    st.header("Configuration")

    primitive = st.selectbox(
        "Select Cryptographic Primitive",
        options=[
            "LWE (Learning With Errors)",
            "CKKS / RLWE (Homomorphic Encryption)",
            "RSA (Factoring)",
            "ECC (Elliptic Curve / SECP256K1)",
            "Symmetric & Hash Brute-force",
        ],
    )

    st.divider()

    # Dynamic sliders based on primitive
    if primitive == "LWE (Learning With Errors)":
        st.subheader("LWE Parameters")
        n = st.slider("Lattice Dimension $n$",
                      min_value=256, max_value=2048, step=256, value=512)
        log2_q = st.slider("Modulus $\\log_2 q$",
                           min_value=10, max_value=60, step=1, value=32)
        sigma = st.slider("Noise Standard Deviation $\\sigma$",
                          min_value=1.0, max_value=8.0, step=0.1, value=3.2)
        endpoint = "/evaluate/lwe"
        params_fn = lambda: {"n": n, "q": 2 ** log2_q, "sigma": sigma}
        extra_context = {"log2_q": log2_q}

    elif primitive == "CKKS / RLWE (Homomorphic Encryption)":
        st.subheader("CKKS / RLWE Parameters")
        N = st.slider("Ring Dimension $N$",
                      min_value=1024, max_value=32768, step=1024, value=4096)
        log2_Q = st.slider("Coefficient Modulus $\\log_2 Q$",
                           min_value=100, max_value=3000, step=50, value=200)
        sigma = st.slider("Noise Standard Deviation $\\sigma$",
                          min_value=1.0, max_value=8.0, step=0.1, value=3.2)
        endpoint = "/evaluate/ckks"
        params_fn = lambda: {"N": N, "Q": 2 ** log2_Q, "sigma": sigma}
        extra_context = {"log2_Q": log2_Q, "N": N}

    elif primitive == "ECC (Elliptic Curve / SECP256K1)":
        st.subheader("ECC Parameters")
        curve_bits = st.select_slider(
            "Curve Size (bits)",
            options=[160, 224, 256, 384, 521],
            value=256,
        )
        endpoint = "/evaluate/ecc"
        params_fn = lambda: {"curve_bits": curve_bits}
        extra_context = {}

    elif primitive == "Symmetric & Hash Brute-force":
        st.subheader("Brute-force Parameters")
        algo = st.selectbox(
            "Hash Algorithm",
            options=[
                "MD5 (Fast Hash)",
                "SHA-256 (Fast, ASIC-dominated)",
                "NTLM (Extremely Fast, Windows AD)",
                "WPA2 PBKDF2 (Slow Hash)",
                "Argon2 (Memory-Hard, Modern Standard)",
            ],
        )
        length = st.slider("Password Length",
                           min_value=6, max_value=20, value=8)
        charset_name = st.selectbox(
            "Charset",
            options=["Digits (10)", "Hexadecimal (16)", "Alphanumeric (62)", "Full ASCII (95)"],
        )
        charset_map = {"Digits (10)": 10, "Hexadecimal (16)": 16,
                       "Alphanumeric (62)": 62, "Full ASCII (95)": 95}
        charset_size = charset_map[charset_name]
        endpoint = "/evaluate/bruteforce"
        params_fn = lambda: {"algo": algo, "length": length, "charset_size": charset_size}
        extra_context = {"charset_name": charset_name}

    else:  # RSA
        st.subheader("RSA Parameters")
        modulus_bits = st.select_slider(
            "Modulus Size (bits)",
            options=[1024, 2048, 3072, 4096, 6144, 7680, 8192, 15360],
            value=2048,
        )
        endpoint = "/evaluate/rsa"
        params_fn = lambda: {"modulus_bits": modulus_bits}
        extra_context = {}

    st.divider()
    evaluate = st.button("Evaluate Security", type="primary", use_container_width=True)

# ---- Main Body ----
if evaluate:
    params = params_fn()

    with st.spinner("Estimating security level..."):
        try:
            resp = requests.get(f"{BACKEND_BASE}{endpoint}", params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
        except requests.ConnectionError:
            st.error(f"Cannot reach the backend at {BACKEND_BASE}")
            st.info("Start it with: `cd backend && uvicorn main:app --host 127.0.0.1 --port 8000`")
            st.stop()
        except Exception as e:
            st.error(f"Backend error: {e}")
            st.stop()

    # ---- Brute-force display (special case: no lambda / delta) ----
    if primitive == "Symmetric & Hash Brute-force":
        st.subheader("Search Space")
        st.metric(label="Total Keyspace",
                  value=data["search_space_display"],
                  help=f"{data['charset_size']}^{data['length']} = {data['search_space']:.2e}")

        st.subheader("Multi-Adversary Brute-force Comparison")
        rows = []
        for r in data["results"]:
            rows.append({
                "Threat Actor (Hardware)": r["actor"],
                "Hash Rate": r["hash_rate"],
                "Estimated Time to Crack": f"{r['indicator']} {r['time_display']}",
            })
        st.dataframe(rows, use_container_width=True, hide_index=True)

        # Legend
        st.caption("\U0001f534 < 1 day  |  \U0001f7e1 < 1 year  |  \U0001f7e2 > 1 year  |  Unbreakable > 10⁵ years")

        with st.expander("Brute-force Attack Model & Assumptions", expanded=False):
            st.markdown(f"""
            **Attack Model:** Exhaustive key-search (brute-force) over the full keyspace.

            **Assumptions:**
            - The attacker has obtained a password hash and can test guesses offline.
            - No salting / key-stretching beyond the algorithm's native cost is applied.
            - Hardware rates are approximate and represent sustained throughput.

            **Algorithm:** {data["algo"]} ({data["algo_family"]} hash family)
            **Password length:** {data["length"]} characters
            **Charset:** {extra_context["charset_name"]} ({data["charset_size"]} symbols)
            **Total keyspace:** {data["search_space"]:.2e} possibilities

            ---
            The time-to-crack is computed as $T = \\frac{{\\text{{keyspace}}}}{{\\text{{hash rate}}}}$
            for each hardware profile. Real-world attacks may be faster due to
            dictionary attacks, rainbow tables, or ASIC optimisations. Use a
            strong, salted key-derivation function (e.g., Argon2, bcrypt) to
            mitigate brute-force threats.
            """)
        st.stop()

    # ---- Metrics (non-bruteforce primitives) ----
    lam = data["security_level_bits"]
    assessment = data["assessment"]

    if primitive == "ECC (Elliptic Curve / SECP256K1)":
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(label="Classical Security $\\lambda$", value=f"{lam} bits",
                      delta=assessment, delta_color="normal" if lam >= 112 else "inverse")
        with col2:
            st.metric(label="Curve Size",
                      value=f"{data['curve_bits']}-bit")
        with col3:
            st.metric(label="Quantum Security",
                      value="0 bits", delta="broken by Shor", delta_color="inverse")
    elif primitive != "RSA (Factoring)":
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(label="Security Level $\\lambda$", value=f"{lam} bits",
                      delta=assessment, delta_color="normal" if lam >= 112 else "inverse")
        with col2:
            st.metric(label="Root Hermite Factor $\\delta$",
                      value=f"{data['root_hermite_factor']:.6f}")
        with col3:
            st.metric(label="BKZ Block Size $\\beta$",
                      value=f"{data['estimated_bkz_block_size']:.0f}")
    else:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(label="Security Level $\\lambda$", value=f"{lam} bits",
                      delta=assessment, delta_color="normal" if lam >= 112 else "inverse")
        with col2:
            st.metric(label="RSA Modulus Size",
                      value=f"{data['modulus_bits']}-bit")
        with col3:
            st.metric(label="GNFS $\\log_2$ Cost",
                      value=f"{data['gnfs_log2_cost']}")

    # ---- Colour-coded callout ----
    if primitive == "ECC (Elliptic Curve / SECP256K1)":
        st.warning(
            ":warning: **Quantum Vulnerability:** Shor's algorithm solves the ECDLP "
            "in polynomial time on a fault-tolerant quantum computer, reducing ECC "
            "security to effectively **0 bits**. ECC offers no post-quantum security. "
            "The classical estimate above assumes an attacker without access to a "
            "large-scale quantum computer."
        )

    if lam < 80:
        st.error(f"Security level $\\lambda = {lam}$ bits is **insecure** (below 80-bit).")
    elif lam < 112:
        st.warning(f"Security level $\\lambda = {lam}$ bits is **weak** (below 112-bit).")
    elif lam < 128:
        st.info(f"Security level $\\lambda = {lam}$ bits is **acceptable** (near 128-bit).")
    else:
        st.success(f"Security level $\\lambda = {lam}$ bits is **strong** (128-bit or higher).")

    # ---- Explanation ----
    with st.expander("Provable Security & Hardness Assumption", expanded=False):
        st.markdown(f"""
        **Hardness Assumption:** {data["hardness_assumption"]}

        {data["explanation"]}
        """)

        if primitive == "LWE (Learning With Errors)":
            st.markdown(f"""
            ---
            **Parameters used:**
            - $n = {data["n"]}$ (lattice dimension)
            - $q = {data["q"]}$ (modulus, $\\log_2 q = {extra_context["log2_q"]}$)
            - $\\sigma = {data["sigma"]}$ (noise standard deviation)
            """)
        elif primitive == "CKKS / RLWE (Homomorphic Encryption)":
            st.markdown(f"""
            ---
            **Parameters used:**
            - $N = {data["N"]}$ (ring dimension)
            - $Q = {data["Q"]}$ (coefficient modulus, $\\log_2 Q = {extra_context["log2_Q"]}$)
            - $\\sigma = {data["sigma"]}$ (noise standard deviation)
            """)
        elif primitive == "ECC (Elliptic Curve / SECP256K1)":
            st.markdown(f"""
            ---
            **Parameters used:**
            - Curve size: {data["curve_bits"]} bits
            - Classical attack: Pollard's rho — $O(2^{{{data['classical_security_bits']}}})$
            - Quantum attack: Shor's algorithm — polynomial time
            """)
        else:
            st.markdown(f"""
            ---
            **Parameters used:**
            - RSA modulus size: {data["modulus_bits"]} bits
            """)

    # ---- Trade-off Analysis (LWE & CKKS only) ----
    if primitive in ("LWE (Learning With Errors)", "CKKS / RLWE (Homomorphic Encryption)"):
        st.divider()
        st.subheader("Security Trade-off Analysis")

        if primitive == "LWE (Learning With Errors)":
            x_label = "Lattice Dimension $n$"
            curve_endpoint = "/evaluate/lwe/curve"
            curve_params = {"q": 2 ** log2_q, "sigma": sigma}
            explanation = (
                "Increasing the lattice dimension $n$ exponentially improves security "
                "for a fixed modulus $q$ and noise level $\\sigma$. Each additional "
                "64 dimensions raises the root Hermite factor closer to 1, requiring "
                "a larger BKZ block size to break the scheme."
            )
        else:
            x_label = "Coefficient Modulus $\\log_2 Q$"
            curve_endpoint = "/evaluate/ckks/curve"
            curve_params = {"N": N, "sigma": sigma}
            explanation = (
                "Increasing the coefficient modulus $Q$ significantly reduces "
                "security bits $\\lambda$ for a fixed ring dimension $N$. This is "
                "because larger $Q$ means a larger $Q/\\sigma$ ratio, which inflates "
                "the root Hermite factor $\\delta$ and makes the lattice problem "
                "easier for BKZ to solve."
            )

        with st.spinner("Generating trade-off curve..."):
            try:
                curve_resp = requests.get(
                    f"{BACKEND_BASE}{curve_endpoint}", params=curve_params, timeout=30
                )
                curve_resp.raise_for_status()
                curve_data = curve_resp.json()
            except Exception:
                st.warning("Could not load trade-off curve data.")
                curve_data = None

        if curve_data:
            chart_df = {"x": [p["x"] for p in curve_data],
                        "y": [p["y"] for p in curve_data]}
            st.line_chart(chart_df, x="x", y="y", x_label=x_label,
                          y_label="Security Level $\\lambda$ (bits)")
            st.caption(explanation)

else:
    st.info("Select a cryptographic primitive, adjust parameters in the sidebar, "
            "and click **Evaluate Security** to begin.")
